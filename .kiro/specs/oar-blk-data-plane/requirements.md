# Requirements Document — oar-blk: the storage data plane

## Introduction

oar-blk gives VMs local block storage that is encrypted per VM below the
guest: the guest sees an ordinary plaintext virtio-blk disk and holds no
key, the media holds only ciphertext, and the host never sees either keys
or plaintext. Volumes are independent of VMs: they can persist after a VM
is destroyed or be crypto-erased with it. VMs boot from attached volumes,
so the host never handles guest images. A volume may instead be an
**image volume**: a read-only base image in S3-compatible object storage,
fetched lazily by the storage role, with the VM's writes kept in an
ephemeral overlay that is discarded when the volume is released.

Two backing implementations are in scope: a **storage endpoint board**
that encrypts in its own firmware (implemented first), and **self-encrypting
NVMe** with per-namespace locking behind a storage manager VM (later).

### What this spec does not cover

- Guest-side encryption (explicitly not wanted: the guest must not decrypt).
- Snapshots, replication and moving volumes between servers: network
  volumes in `block-volume-service` cover these.
- The key hierarchy itself (`helm-control-plane` Requirement 4).

## Glossary

- **Volume** — a block device with its own volume key, owned by one VM.
- **Storage function** — the virtio-blk PCI function presenting one
  attachment to one VM.
- **Crypto-erase** — making a volume unreadable by destroying its key.
- **Image** — an immutable disk image in an S3-compatible object store:
  a data object read in fixed-size chunks and a manifest listing each
  chunk's SHA-256. An image is named by the SHA-256 of its manifest.
- **Image volume** — a volume whose blocks come from an image until the
  guest writes them; writes go to an ephemeral overlay.
- **Overlay** — the local copy-on-write store holding an image volume's
  written blocks, encrypted under a key that exists only for one
  attachment.

## Requirements

### Requirement 1: virtio-blk functions

#### Acceptance Criteria

1. Each attachment SHALL be a modern virtio-blk PCI device with MSI-X,
   presenting the volume's plaintext.
2. The device SHALL support FLR; after reset it SHALL hold no key and no
   plaintext.
3. The device logic SHALL be built on the shared virtio core with the same
   two transports as oar-net.

### Requirement 2: Transparent per-VM encryption

**User Story:** As a tenant, I want my disks encrypted with keys only my
VM's attachments can use, without running any encryption in my guest.

#### Acceptance Criteria

1. Data at rest SHALL be encrypted with AES-256-XTS using the volume key,
   with the sector number as tweak.
2. The volume key SHALL be held only in the storage role's RAM, and only
   while the volume is attached.
3. WHEN the volume is detached, the function is reset, or the role loses
   power THEN the key SHALL be zeroized.
4. The guest SHALL need no key and no encryption software.
5. Keys SHALL arrive only from helm over this role's own sideband segment.

### Requirement 3: Volume lifecycle

#### Acceptance Criteria

1. `CREATE_VOLUME {vol_id, owner_vm, size}` SHALL allocate space and store
   the wrapped volume key with the volume's metadata.
2. `ATTACH_VOLUME` / `DETACH_VOLUME` SHALL follow the device-pool flow
   (assign, hot-plug, reset, clean).
3. `DELETE_VOLUME` SHALL crypto-erase (helm destroys the wrapped key) and
   then release space.
4. Destroying a VM with `persist_volumes = false` SHALL crypto-erase all of
   that VM's volumes.
5. `REWRAP_VOLUME` SHALL be the only way a volume changes owner.

### Requirement 4: Boot from volume

#### Acceptance Criteria

1. A VM SHALL be bootable from an attached volume through the guest
   firmware's virtio-blk support, with no host-supplied image.

### Requirement 5: Self-encrypting NVMe option (later)

#### Acceptance Criteria

1. The design SHALL allow volumes on TCG Opal NVMe namespaces, each with
   its own locking credential delivered by helm, exposed through SR-IOV VFs
   under a storage manager VM.
2. Drives used this way SHALL have FIPS 140-3 validation; SPDM support is
   preferred.

### Requirement 6: Integrity of the device against the guest

#### Acceptance Criteria

1. All virtqueue descriptors and request headers from the guest SHALL be
   bounds-checked; out-of-range sectors SHALL fail the request, never
   wrap or touch another volume.
2. The virtio-blk request parser SHALL have a fuzz target.

### Requirement 7: Testing

#### Acceptance Criteria

1. Unit tests SHALL cover XTS against published test vectors (IEEE 1619).
2. harbor SHALL verify: plaintext in the guest, only ciphertext in the
   backing file, crypto-erase makes data unrecoverable, a detached volume
   attached to another VM without rewrap fails, and boot from volume.
3. Image volumes SHALL be tested against a local S3-compatible server
   (or an in-process mock where no server is available): lazy fetch,
   digest mismatch, readahead, cache eviction, overlay read-back and
   discard on detach, and boot from an image volume in harbor.

### Requirement 8: Image volumes from object storage

**User Story:** As an operator, I want VMs to boot from shared base images
kept in object storage, fetched only as the guest reads them, with each
VM's changes thrown away when its volume is released, so that launching a
VM does not copy a whole image and leaves nothing behind.

#### Acceptance Criteria

1. An image volume SHALL present an image read-only at the bottom and
   the guest's writes on top: a block the guest has written SHALL read
   back as written; any other block SHALL read as the image's block, or
   as zeros past the image's end when the volume is larger than the
   image.
2. Image data SHALL be fetched on demand from an S3-compatible object
   store with ranged GETs, one chunk at a time, and SHALL NOT be copied
   in full before the guest can boot.
3. Every fetched chunk SHALL be checked against its SHA-256 in the
   manifest, and the manifest against the image name (its own SHA-256),
   before any of its bytes reach a guest; a mismatch SHALL fail the read
   and never be cached.
4. Fetched chunks SHALL be kept in a bounded local cache shared by every
   volume of the same image, evicting least recently used chunks.
5. WHEN reads of an image volume are sequential THEN the role SHALL
   fetch the following chunks ahead of the guest.
6. Writes SHALL go only to the volume's overlay, never to the object
   store or the cache. The overlay SHALL be encrypted with AES-256-XTS
   under an ephemeral key that helm creates for the attachment and never
   wraps or stores.
7. WHEN the volume is detached, its function reset by FLR, or the role
   restarts THEN the overlay and its key SHALL be discarded; an image
   volume SHALL never be reattached with an earlier attachment's writes.
8. An image SHALL be stored either in plaintext (public images) or
   encrypted with AES-256-XTS under an image key that helm holds wrapped
   and delivers with the ephemeral key; the cache SHALL hold only what
   the object store holds.
9. Object store credentials SHALL be read-only and scoped to the image
   bucket; the role SHALL refuse a response that is malformed, longer
   than requested, or not the range it asked for.
10. A fetch SHALL have a deadline and bounded retries; WHEN a chunk
    cannot be fetched THEN the read SHALL complete with IOERR rather
    than hang the guest.
11. The manifest and HTTP response parsers SHALL have fuzz targets.
