# Design Document — oar-blk: the storage data plane

## Overview

```
 guest virtio-blk (plaintext)
      │ DMA through the IOMMU into guest memory
 ┌────┴──────────────────────────────── oar-blk ─┐
 │ VirtioBlkFunction ─► RequestParser (bounds)   │
 │        │                                      │
 │        ▼                                      │
 │ XtsCipher(volume key, tweak = LBA) ◄─ KeySlot │◄── helm: deliver_key / drop_key
 │        │                                      │      (own sideband segment)
 │        ▼                                      │
 │ Backend: file (harbor) / NVMe (board)         │
 └───────────────────────────────────────────────┘
```

## Components

- **VirtioBlkFunction** — virtio-blk on the shared core; `VIRTIO_BLK_T_IN`,
  `T_OUT`, `T_FLUSH`, `T_GET_ID`; discard later. A `virtio::Device` behind
  `PciFunction`, so both transports serve it as they serve virtio-net.
  Offers VERSION_1, ACCESS_PLATFORM, INDIRECT_DESC, EVENT_IDX, SIZE_MAX,
  SEG_MAX, BLK_SIZE, FLUSH, RO when read-only and MQ with several queues;
  `size_max` is `max_transfer_bytes / seg_max` (at least one page), so no
  request a driver builds exceeds the parser's transfer cap. Requests are
  served synchronously from a per-queue bounce buffer: writes copy guest
  plaintext once, encrypt in place and hand only ciphertext to the
  backend; reads decrypt in place, copy out and wipe. Without a key IN and
  OUT fail with IOERR. FLR (`function_reset`) and helm's `drop_key` wipe
  the key; a driver reset (status 0) does not, because the guest driver
  resets the device on every probe. helm therefore delivers the key after
  the VMM has opened (and reset) the function during attach.
- **RequestParser** — validates header, sector range against the volume
  size, and descriptor chain shapes before any I/O. It takes the readable
  and writable buffers of a chain the shared virtqueue already validated,
  so it does not depend on the virtio core. Lengths and start sectors
  must be whole logical blocks (512 B or 4 KiB, matching the XTS data
  unit); a request without a writable status byte cannot be completed
  and is left to the transport to treat as a broken chain.
- **KeySlot** — holds at most one `ScopedKey`-equivalent; zeroizes on
  `drop_key`, FLR, detach, or process exit (`OPENSSL_cleanse`, locked
  memory, excluded from core dumps with `MADV_DONTDUMP`). The key page is
  also `MADV_WIPEONFORK`, so forked helpers never inherit it. A second
  `deliver_key` without a `drop_key` is refused and keeps the held key.
  `harden_process()` disables core dumps and ptrace for the whole role.
- **XtsCipher** — OpenSSL EVP `aes-256-xts`, 512-byte or 4 KiB data units.
  The tweak is the data unit number, little-endian (IEEE 1619): for 4 KiB
  units that is the 4 KiB block index, i.e. the 512-byte sector number
  divided by 8, fixed per volume at creation. Equal key halves are
  rejected. One cipher per I/O queue: it reuses its OpenSSL contexts.
- **Backend** — harbor: a sparse file per volume plus a metadata header
  (volume ID, owner VM, wrapped key, size). Board: NVMe via the board's
  root-complex controller. `BlockBackend` is the seam: volume byte
  offsets, size, read, write, flush. The file header is one 4 KiB block
  so data stays aligned for both block sizes; the wrapped key is opaque
  to oar-blk (helm authenticates it on unwrap) and a SHA-256 over the
  fields catches corruption first. Delete is crypto-erase in helm plus
  `FileBackend::erase`, which overwrites the header, the file's only
  copy of the wrapped key, before unlinking.

- **BlkRole** (`src/oar/blk/blk_role.*`) — the role's answer to helm's
  sideband (`helm::OarHandler`): volume files `vol-<id>.akv` in one
  directory, and a fixed set of functions, one per transport. A transport
  lives as long as the role (L0 QEMU attaches at boot), so what it serves
  changes: between attachments a placeholder (virtio-blk over an empty
  backend, never keyed), during one the volume's own `VirtioBlkFunction`.
  All of them have the same queues, hence the same PCI shape, which is
  what lets the vfio-user binding retarget without the client noticing.
  `prepare_function` opens the volume (owner checked against the header)
  and calls `await_key`; `clean_function` drops the key and puts the
  placeholder back; `delete_volume` closes a volume still open (a
  destroyed VM's) before erasing it, and a missing file counts as
  deleted so retries succeed; `rewrap_volume` refuses an open volume.
- **ak-oar-blk** (`oar_blk_main.cpp`, `-DAK_VFIO_USER=ON`) — the harbor
  process: one vfio-user socket per function, helm's sideband on a
  listening SOCK_SEQPACKET socket (re-listening if helm goes away), core
  dumps and ptrace off before anything is served.

## Image volumes (Requirement 8)

An image volume is a read-only base image in an S3-compatible object
store with a per-attachment, throwaway overlay on top. It reuses the
whole data path above `BlockBackend` unchanged: the function still
encrypts every write and decrypts every read with the key helm delivered,
so all the new code sits behind the backend seam.

```
 VirtioBlkFunction ── XtsCipher(K_eph) ──► LazyImageBackend (BlockBackend)
                                             │ per logical block:
                                             ├─ written?  Overlay (O_TMPFILE, ciphertext under K_eph)
                                             ├─ in image? ChunkCache ─miss─► Fetcher ─► ObjectStore (S3 GET Range)
                                             │              (shared per image)      readahead
                                             └─ past end? zeros
                                    base and zero blocks: [decrypt K_img] → encrypt K_eph
```

### Keys

- **K_eph**, the attachment's volume key: helm draws it from `RAND_bytes`
  at ATTACH_VOLUME, delivers it with the usual `deliver_key` after hull's
  ok, and never wraps or stores it. The function encrypts writes with it,
  so the overlay holds only ciphertext; dropping it (detach, FLR,
  `drop_key`, role exit) crypto-erases the overlay.
- **K_img**, only for encrypted images: the image's AES-256-XTS key,
  held wrapped by helm like a volume key and delivered alongside K_eph.
  Public images are stored in plaintext and have none.

The function expects every block the backend returns to be ciphertext
under K_eph. The backend therefore re-encrypts the blocks it takes from
the image (or synthesises as zeros): decrypt with K_img if the image is
encrypted, then encrypt with K_eph at the same logical block number. It
holds K_eph (and K_img) only as `XtsCipher` contexts, which OpenSSL
cleanses when freed, loaded and dropped together with the function's
key. This costs one or two extra XTS passes on image
reads (several GB/s with AES-NI, far above object store throughput) and
keeps the function's contract and its fuzzing intact. Plaintext exists
only transiently in the backend's buffer, which is wiped, in the same
process that already decrypts for the guest.

When the key is dropped, the backend discards the overlay too (bitmap
cleared, file hole-punched): a later key cannot read the old blocks, and
the volume can never come back with an earlier attachment's writes.

### Image format

An image is two immutable objects under one name, the lowercase hex
SHA-256 of its manifest (content addressing: the attach request carries
the name, so the object store cannot substitute a manifest):

```
<prefix>/<name>/manifest
<prefix>/<name>/data       image_bytes bytes, read with Range GETs
```

The manifest is little-endian, decoded with `ak::wire` as untrusted input
(`fuzz/fuzz_image_manifest.cpp`):

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `AKIMAGE\0` |
| 8 | 2 | version (1) |
| 10 | 2 | flags: bit 0 encrypted (AES-256-XTS); other bits zero |
| 12 | 4 | logical block size: 512 or 4096 |
| 16 | 1 | chunk shift: 16..22 (64 KiB to 4 MiB; 20 = 1 MiB by default) |
| 17 | 7 | zero |
| 24 | 8 | image bytes: non-zero, whole logical blocks |
| 32 | 4 | chunk count: ceil(image bytes / chunk size), at most 2^20 |
| 36 | 4 | zero |
| 40 | 16 | image key ID (zero unless encrypted) |
| 56 | 32 × count | SHA-256 of each chunk as stored; all zero bytes = a hole |

The last chunk may be short. A hole is a chunk of plaintext zeros that
is never stored, fetched or cached, so sparse images stay cheap; in an
encrypted image too, which reveals which chunks are empty as a sparse
file would. The manifest is exactly
56 + 32 × count bytes; anything else is refused. For encrypted images the
XTS data unit is the logical block and the tweak its block number, as
for volumes, so the image is a valid ciphertext volume image under K_img.

`ak-image-pack` (`image_pack.*`, task 12) turns a raw disk image into the
two objects in a local directory, `DIR/<name>/{manifest,data}`, and
prints the name. It reads one chunk at a time; a chunk of zeros becomes a
hole and is not written, so the data object is sparse. With `--key-file`
(64 raw key bytes) and `--key-id` it encrypts every stored chunk under
K_img exactly as the backend decrypts it. Packing is deterministic, and
the output is renamed into place only once it is complete and synced. It
never talks to the object store: publishing is an upload of that
directory with the publisher's own write credentials, so the storage
role's credentials can stay read-only (8.9).

### Components

- **ImageManifest** (`image_manifest.*`) — the codec above plus
  `manifest_name()` (SHA-256), chunk geometry helpers and the check that
  a fetched chunk matches its digest.
- **ObjectStore** (`object_store.hpp`) — the seam: `get_range(key,
  offset, length, deadline)` into a caller buffer. `S3ObjectStore`
  (`s3_object_store.*`) implements it with HTTP/1.1 over TCP or TLS
  (server-authenticated, the store's CA bundle), path-style URLs (MinIO
  and most S3-compatible stores; virtual-host style as an option), and
  AWS Signature V4 (`UNSIGNED-PAYLOAD` is not needed: a GET's payload hash
  is the empty-string SHA-256), or anonymous for public buckets. The
  response parser (`http_response.*`, `fuzz/fuzz_http_response.cpp`)
  accepts only `206` with a `Content-Range` equal to the requested range
  and a matching `Content-Length` (or `200` with the whole object when the
  range covers it); no chunked encoding, header block capped at 16 KiB,
  body never longer than asked. Connections are kept alive and reused.
  Credentials come from the role's store configuration and should be a
  read-only key scoped to the image bucket.
- **Fetcher** — a few worker threads (default 4), each with its own
  connection. Demand fetches go ahead of readahead; a chunk has at most
  one fetch in flight and every waiter shares it. Each fetch has a
  deadline (default 5 s) and up to 3 retries with jittered backoff on
  connection errors and 5xx; a digest mismatch is not retried against the
  same response but counts as a failed attempt.
- **ChunkCache** — one per image name, shared by every volume of that
  image in the role: a sparse `O_TMPFILE` in the cache directory, an
  in-memory index of resident chunks, and one byte budget for all images
  in the role. Chunks enter only after their digest matched; eviction is
  least recently used at chunk granularity (`FALLOC_FL_PUNCH_HOLE`), and
  chunks being read are pinned. Once verified, a resident chunk is read
  back from local media without re-hashing: local media is trusted for
  integrity exactly as volume files are. The cache is not persisted
  across role restarts (a later task may add an index that re-verifies
  on first use).
- **Readahead** — per volume: a read that starts where the previous one
  ended (or in the next chunk) doubles a window from 1 up to
  `max_readahead` chunks (default 8); any other read resets it. After
  each read the window of chunks past it is queued for the fetcher at
  low priority, skipping resident chunks and holes.
- **Overlay** — the attachment's writes: a sparse `O_TMPFILE` in the
  overlay directory (never linked, so a crash frees it too) sized to the
  volume, and a bitmap of written logical blocks in memory. A write
  lands in the file first and sets its bits after; a read is split into
  runs of overlay, image and zero blocks. An optional limit on written
  bytes completes writes past it with IOERR. `flush` is a no-op: the
  overlay does not outlive the attachment, and the VM does not outlive a
  host crash.
- **LazyImageBackend** (`lazy_image_backend.*`) — the `BlockBackend` that
  ties these together for one attachment: capacity at least the image
  size (a larger volume reads zeros past the image), `load_key`/
  `drop_key` for its K_eph copy (and K_img), counters (hits, misses,
  fetched bytes, readahead hits, overlay blocks).

### Blocking on a miss

The role serves requests synchronously on one thread, so a demand miss
blocks every function of the role until the chunk arrives or its deadline
passes. Readahead keeps sequential boot reads mostly hitting, but a cold
random read costs a round trip to the store. The fix is asynchronous
completion in `VirtioBlkFunction`: park the request (as `await_key`
already parks requests) and complete it when the fetcher calls back. That
changes the function's request loop, so it is a separate task.

### Lifecycle with helm

| Command | Image volume |
|---|---|
| CREATE_VOLUME | carries an image source (store ID, image name) instead of a new key; the role writes `vol-<id>.akv` with a version-2 header: kind image, store ID, image name, capacity, no wrapped key (or K_img's wrapped key for an encrypted image) |
| ATTACH_VOLUME | `prepare_function` fetches and checks the manifest and opens a LazyImageBackend with an empty overlay; helm creates K_eph and delivers it after hull's ok |
| DETACH_VOLUME | cleaning drops K_eph and closes the overlay: the writes are gone |
| DELETE_VOLUME | removes the descriptor; nothing to crypto-erase but the wrapped K_img copy |
| REWRAP_VOLUME | changes owner; only meaningful for K_img |

On the storage role (task 13, role side):

- **Sideband.** `create_volume` names the image in the reserved field at
  offset 30, now `image_store`. Zero means a disk volume, exactly as
  before. Non-zero means an image volume: a 32-byte image name follows the
  head, then the wrapped key. `key_len` may be 0, for a plain image. A peer
  that predates this refuses the field as a reserved byte set, so it fails
  closed.
- **Volume file.** A version-2 header (`FileBackend::create_image_volume`)
  adds `store_id u16 | reserved u16 | reserved u32 | image name [32]`
  after the key field, under the same SHA-256. The file is just that 4 KiB
  header. `FileBackend::open` refuses it as `image_volume`, and
  `read_metadata` reads either kind.
- **Prepare.** `prepare_function` reads the header. For an image volume it
  fetches `<prefix>/<name>/manifest` from the configured store (10 s
  deadline) and checks it against the name. It refuses an encrypted image
  until task 15. It then opens the image in the shared `ChunkCache` and
  serves a `LazyImageBackend` with a fresh overlay. The capacity must hold
  the image.
- **Keys.** `deliver_key` gives the key to the function and to the
  backend. `drop_key`, cleaning and FLR take it from both, which discards
  the overlay.
- **Configuration.** ak-oar-blk is configured with
  `--image-store ID=PATH` (one file per store: endpoint, bucket, prefix,
  region, style, CA file and read-only credentials; see
  `image_store_config.hpp`), `--image-cache DIR` and
  `--image-cache-bytes N`. `create_volume` naming a store the role does
  not have answers `unsupported`.
- **Rewrap.** `rewrap_volume` of an image volume fails: there is no key to
  rewrap until task 15.

helm's half (task 13, helm side) is still open. It covers CREATE_VOLUME
with an image source on the mailbox, no volume key for image volumes,
K_eph drawn and delivered at ATTACH_VOLUME, and ownership kept without a
KeyStore entry.

Open: how a storage board reaches the object store (through an oar-net
function, or its own uplink); on harbor the oar-blk process uses L1's
network.

## Volume lifecycle with helm

helm keeps the wrapped volume keys and the oar-blk role keeps the
volumes; the sideband connects the two (helm-control-plane design,
CommandRouter, for the full rules):

| Command | Before relay (undone on failure) | After hull's ok |
|---|---|---|
| CREATE_VOLUME | create the key; `create_volume` with the wrapped key on the lowest blk slot | — |
| ATTACH_VOLUME | reserve the function (on the volume's slot); `prepare_function` | unwrap, `deliver_key` |
| DETACH_VOLUME | — | release; cleaning drops the key and closes the volume |
| DELETE_VOLUME | — | destroy the key (crypto-erase), `delete_volume` |
| REWRAP_VOLUME | — | rewrap in the KeyStore, `rewrap_volume` |

The key follows hull's ok because hull answers once the VMM has opened the
function, and opening a VFIO device resets it: a key delivered earlier
would be wiped by that FLR. The guest may probe the disk in the gap, so
the function holds its requests until the key comes. A delivery that
fails is reported as a `device_lost` host fault (slot, volume ID) for the
controller to detach. CREATE_VOLUME carries no block size, so volumes are
created with 512-byte blocks; 4 KiB volumes need a body field.

Open: helm keeps wrapped keys only in memory, so after a helm restart it
must reload them from the media (`KeyStore::import_volume_key`); the
sideband has no request to list volumes and their wrapped keys yet.

## Placement notes

A storage board needs one PCIe controller in endpoint mode (backplane) and
one in root-complex mode (SSD). TI J721E-class SoCs fit; RK3588 does not at
useful speed. Throughput target for the first board: about Gen3 x2.

## Testing strategy

- XTS vectors; parser fuzzing; key zeroization checked with a test hook.
- harbor scenarios from Requirement 7.2, including grepping the backing
  file for a known plaintext pattern written by the guest.
- Image volumes: unit tests over an in-memory ObjectStore (lazy fetch,
  holes, digest mismatch, retries and deadlines, readahead, eviction,
  overlay runs, discard on `drop_key`), the S3 client against a local
  MinIO when `AK_S3_TEST_ENDPOINT` is set (skipped otherwise), and boot
  from an image volume in harbor.
