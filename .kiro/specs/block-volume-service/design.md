# Design Document — hold: the fault-tolerant block volume service

## Overview

```
 compute server                                        storage servers
 ┌──────────────────────────────────────────┐
 │ guest ── virtio-blk (plaintext) ──┐      │          ┌──── hold (primary) ─────┐
 │                                   ▼      │  storage │ ReplicaStore: data file │
 │ oar-blk  VirtioBlkFunction               │  network │ + checksums, intents,   │
 │          XtsCipher(K_vol) ◄── helm       │  mTLS    │ hydration, snapshots    │
 │          NetworkVolumeBackend ───────────┼─────────►│      │ REPL_WRITE       │
 │            QoS, CRC32C, retry/redirect   │ cipher-  └──────┼──────────────────┘
 └──────────────────────────────────────────┘ text only        ▼
                     ▲ VolumeKey (HPKE)                 hold (secondary) …
                     │ ReplicaConfig                           │
                     │                                         │ ReplicaConfig, VolumeOp
          controller (kythira EC2 module, Raft): volume catalog, placement,
          epochs and leases, failure handling, snapshots and GC, KMS
                                                               │
                                       S3-compatible object store: snapshots, images
```

A network volume is a set of replicas on **hold** roles. The guest's disk
is still an oar-blk `VirtioBlkFunction` on the compute server, so the
guest, the key path and the device's fuzzing are unchanged: the only new
thing below the function is a `BlockBackend` that sends ciphertext over
the storage network instead of to a local file. Everything the service
stores or sends is ciphertext under the volume key, which only the
compute server's oar-blk ever holds.

The design follows Amazon EBS's published shape — chain-free primary
replication within an availability zone, with an external, strongly
consistent configuration master (EBS's Physalia) deciding membership — and
maps it onto pieces antikythera already has:

| EBS piece | Here |
|---|---|
| Nitro card presents NVMe to the instance | oar-blk presents virtio-blk; XTS in the role, not the guest |
| Storage servers with replicated volumes | hold roles on storage servers, primary + secondaries |
| Physalia (configuration master per volume) | the controller (kythira EC2 module, Raft-replicated) issuing signed, epoch-numbered `ReplicaConfig` frames |
| Snapshots in S3, lazy restore | oar-blk image format v2 in S3, hydrated by hold (same key) or oar-blk (foreign key) |
| KMS envelope encryption | kythira KMS data key per lineage, rewrapped to each attaching helm |

## Volume kinds after this spec

| Kind | Where data lives | Survives server loss | Movable | Use |
|---|---|---|---|---|
| Local volume | file/namespace behind one server's oar-blk | no | detached, by conversion (Req 8.6) | fastest; instance-store-like persistent scratch |
| Image volume | S3 image + per-attachment overlay | base yes, writes no | n/a | stateless boot, discarded on detach |
| Network volume | replica set on hold roles | yes | yes, live | EBS-like root and data volumes |

## Roles and placement

- **hold** (`src/hold/`, namespace `ak::hold`, binary `ak-hold`) is a new
  data-plane role. Like every oar it is untrusted and contained: it sees
  only ciphertext, opaque IDs and checksums, and talks to helm over its
  own sideband segment. On hardware it runs on a storage board with NVMe
  in the server's storage slots (backplane Requirement 3); a dense storage
  server may later run it in a storage manager VM over NVMe VFs. In harbor
  it is a process per storage server storing replicas as files in an XFS
  directory.
- A **storage server** is any antikythera server with a hold role. A
  server can be compute only, storage only, or both; placement treats
  them alike but never relies on co-location.
- **oar-blk** gains an initiator backend; it needs a route to the storage
  network, which is the management fabric (see "Storage traffic on the
  management fabric"). This also answers oar-blk design's open question
  of how a storage board reaches the object store: over the same segment.
- The **controller** owns all volume state (Requirement 6.1). helm
  forwards its frames to the roles and its roles' reports back, as it does
  for oar-net's `MapUpdate`. None of this goes through the mailbox except
  attach and detach, which change the VM.

## Storage traffic on the management fabric

The storage network is the management fabric: the Ethernet that already
carries helm's controller link (backplane Requirement 3.2, controller
Requirement 2.1). There is no separate storage fabric and no storage
traffic on the tenant VPC fabric.

- **Ports.** Every oar-blk and hold board gets a management-fabric port
  (a backplane amendment for storage-capable data-plane slots), separate
  from helm's own management port. The object store is reached the same
  way.
- **Segmentation.** Data-plane roles are untrusted, while helm's
  controller link is the server's most trusted network path, so the two
  never share a segment: storage traffic runs on a storage VLAN (and
  address range) of its own, and the top-of-rack switches refuse traffic
  from it to helm and controller addresses. A compromised board can reach
  other storage roles, which authenticate every session (Requirement
  13.2) and see only ciphertext, but not the control plane
  (Requirement 13.5).
- **Priority.** The fabric marks three classes, with strict priority for
  the first and weighted sharing below it: control (controller link,
  lease renewals and reports through helm), storage I/O (initiator to
  primary, replication), and background (rebuild, resync, hydration,
  scrub, snapshot upload). hold and oar-blk set DSCP/802.1p on their
  sockets; helm marks its own. Leases ride the control class, so a
  saturated storage segment cannot cost a healthy primary its lease
  (Requirement 13.6).
- **Sizing.** Every guest write crosses the fabric once to the primary
  and once more per secondary, so a server's management uplink must be
  sized for storage, not just for control: on the busiest link, about
  `replicas` × write bandwidth plus reads, plus the rebuild budget. The rebuild budget in
  "Resync and rebuild" is a fraction of the storage class's share, not of
  the whole link. The 1 TiB-per-hour rebuild target (Requirement 7.6)
  needs about 300 MB/s of background capacity, so a 25 GbE management
  uplink is the practical floor for storage servers.
- **harbor.** The storage segment is a VLAN on harbor's management
  bridge, with the per-server namespaces of harbor task 7.

## Protocols

All codecs live in `src/proto/` (roles never include each other's
internals), are little-endian, decoded with `ak::wire` as untrusted input,
strict (exact length, zero reserved bytes, canonical ordering), pinned by
test vectors, and fuzzed.

### ReplicaConfig (controller → helm → hold and oar-blk)

The signed, full, per-volume description at one epoch. Like `MapUpdate`
it is a snapshot, not a delta: applying one is idempotent and a role that
missed epochs catches up from the newest. One frame per recipient server
(its `server_id` is inside the signed bytes).

```
ReplicaConfig {
  magic "AKRCFG\0\0", version u16 = 1, key_id u16, server_id u64
  volume_id u64, epoch u64, lineage_id u64
  capacity_blocks u64, block_size u32 (512 | 4096), flags u32
      // multi_attach, io_suspended, impaired, draining
  qos { iops u32, mib_per_s u32, burst_iops u32, burst_mib u32 }
  lease_ms u32, resync_window_s u32
  members [] { server_id u64, endpoint [16], port u16,
               role u8 (primary | secondary | joining | leaving),
               replica_gen u32 }            // strictly increasing server_id
  attachments [] { attachment_id u64, generation u32, server_id u64,
                   mode u8 (rw | ro) }      // at most 16
  source { kind u8 (none | snapshot | image), store_id u32,
           manifest_name [32], hydrate_mib_per_s u32 }
  signature [64]                            // Ed25519 over the above
}
```

Rules checked by the decoder: exactly one primary unless `io_suspended`;
`joining` and `leaving` members are never primary; at most 5 members;
attachment IDs unique; read-write attachments beyond one only with
`multi_attach`. helm verifies the signature with the controller keys it
already holds for `MapUpdate`; each role re-checks the epoch order.

### VolumeOp (controller → helm → hold)

Signed one-shot operations that are not membership: `snapshot_prepare`,
`snapshot_commit`, `snapshot_abort`, `snapshot_upload`, `clone`, `scrub`,
`delete_replica`. Each carries `volume_id`, the epoch it was issued in and
a controller `op_id`; roles execute an `op_id` at most once and report its
outcome, so the controller can resend freely.

### VolumeKey (controller → helm, controller link only)

```
VolumeKey { server_id u64, volume_id u64, attachment_id u64, generation u32,
            hpke_enc [32], wrapped_key [64 + 16] }
```

The lineage's AES-256-XTS key, wrapped by kythira KMS directly to this
helm's secure-element X25519 key with HPKE (RFC 9180: DHKEM(X25519,
HKDF-SHA256), HKDF-SHA256, AES-256-GCM; the other fields are the AAD).
helm opens it inside the secure element, keeps it as a `ScopedKey` for
the attachment's lifetime and delivers it with the existing `deliver_key`.
It never touches the mailbox or the host (Requirement 12.2-12.3).

### Reports (hold and oar-blk → helm → controller)

Additions to `src/proto/report.hpp`:

- `replica_status` per replica: volume, epoch applied, role, state
  (`in_sync`, `joining`, `stale`), last sequence, commit sequence, bytes
  synced of total, lease remaining, checksum errors and repairs,
  hydration progress, I/O counters (Requirement 10.5).
- `volume_fault`: volume, epoch, reporter, kind (`member_timeout`,
  `primary_timeout`, `stale_epoch`, `checksum_unrepairable`,
  `media_error`, `lease_lost`), suspect member.
- `attachment_status`: attachment, generation, state (`attached`,
  `eject_requested`, `released`, `fenced`), in-flight count.
- `demotion_confirmed`, `op_outcome` (for `VolumeOp`), `snapshot_progress`.

### hold wire protocol (oar-blk ↔ hold, hold ↔ hold)

TCP with TLS 1.3 (`src/tls`), mutually authenticated with per-role
certificates the controller's CA issues at enrollment (the role creates
its key; helm relays the CSR). The certificate binds the `server_id`,
which is what a hold role checks against the ReplicaConfig
(Requirement 13.2); its packets carry the storage I/O class, or the
background class for rebuild, hydration and scrub sessions. A session is opened per (volume, peer) with `HELLO`
naming the volume, epoch, and either the attachment and its generation
(initiator) or the member's `replica_gen` (peer).

Every frame starts with a 72-byte header (replication frames carry `seq`
and `commit_seq` at the start of their payload):

```
magic u32 "AKHW", version u8, opcode u8, flags u16, payload_len u32,
status u16, rsvd u16, request_id u64, volume_id u64, epoch u64,
attachment_id u64, generation u32, blocks u32, lba u64,
rsvd u32, header_crc32c u32
```

| Opcode | From → to | Meaning |
|---|---|---|
| `HELLO` / `HELLO_OK` | any | open a session for a volume; refuses stale epoch or unknown attachment |
| `READ` | initiator → primary | read blocks; reply carries data + one CRC32C per block |
| `WRITE` | initiator → primary | write blocks with per-block CRC32C; flag `HYDRATE` = only fill unwritten blocks of an unhydrated chunk |
| `WRITE_ZEROES`, `DISCARD` | initiator → primary | later virtio-blk features; zero / punch |
| `FLUSH` | initiator → primary | barrier only: every completed write is already durable |
| `REPL_WRITE` / `REPL_ACK` | primary → member | ordered replication with `seq` and `commit_seq` |
| `INTENTS` | new primary → member | fetch uncommitted extents for reconcile |
| `SYNC_DATA` | primary → joining/stale | region copy for resync and rebuild |
| `HYDRATE_FILL` | primary → member | replicate a chunk the primary hydrated |
| `PING` | any | liveness on idle sessions; carries `commit_seq` |
| `REDIRECT` | hold → initiator | not primary at this epoch; hint of the newer epoch |

Status codes include `stale_epoch`, `fenced`, `not_primary`, `read_only`,
`not_hydrated`, `throttled`, `checksum`, `io_suspended`, `range`. Payload
lengths are bounded by `blocks × block_size` with `blocks ≤ 2048` (1 MiB at
512 B, 8 MiB at 4 KiB, capped at 4 MiB). `fuzz/fuzz_hold_wire.cpp` covers
the header and every payload.

A custom protocol rather than NVMe/TCP or iSCSI: every request must carry
the epoch and attachment generation for fencing, and replication, intent
reconcile, resync and hydration need operations those protocols do not
have. An NVMe/TCP front for third-party initiators can be added later over
the same store.

## ReplicaStore (hold)

One directory per replica, `vol-<id>.<replica_gen>/`:

- `data` — a sparse file of `capacity` bytes holding ciphertext at its
  logical offset, opened `O_DIRECT`, on a filesystem with reflinks (XFS
  with `reflink=1` in harbor; btrfs also works). Reflinks give
  instant snapshot freezes and clones (`FICLONE`).
- `meta` — a 4 KiB header (magic, version, volume ID, replica_gen,
  lineage, epoch last applied, role, capacity, block size, source, SHA-256
  over the fields; `ak::wire`, fuzzed like the volume header), then:
  - **checksums**: CRC32C per block, 4 bytes (0.1 % at 4 KiB blocks);
  - **chunk state** for hydrating volumes: per chunk `unhydrated`,
    `partial` (with a block bitmap) or `hydrated`;
  - **changed chunks** since the last snapshot freeze (bitmap);
  - **intent ring**: the last 4096 replicated writes as (seq, lba,
    blocks), written durably before the data, cleared by `commit_seq`.

Writes are group-committed: a batch of intents is appended and synced
with the data (`pwritev` + `fdatasync` in v1; io_uring with FUA later,
liburing would be an optional `AK_HAS_LIBURING` dependency). A write is
acknowledged only after its batch is durable (Requirement 1.5). The
checksum array is updated after the data; a crash can leave the two out
of step only inside extents still in the intent ring, which the replica
hands to the primary for resync when it returns, so a torn write is
repaired rather than reported as corruption.

Production NVMe on a storage board will want an SPDK blobstore/lvol
backend (snapshots and clones built in); that stays in oar-blk's deferred
SPDK item. `ReplicaStore` is the seam.

## Write and read paths

```
guest write ─► VirtioBlkFunction: encrypt (K_vol, tweak = LBA)
   ─► NetworkVolumeBackend: QoS tokens, CRC32C per block, WRITE(epoch, att, gen)
   ─► primary: check epoch/attachment/mode/QoS/range/CRC; assign seq;
        ├─ local: intent + data, durable
        └─ REPL_WRITE(seq, commit_seq) to every in-sync and joining member
             member: check epoch, CRC; intent + data, durable; REPL_ACK
   ◄─ primary acks the initiator once local + every in-sync member is durable
```

- **Ordering.** The primary assigns `seq` and sends `REPL_WRITE`s to each
  member on one ordered stream. Every replica applies writes whose
  extents overlap in `seq` order (non-overlapping writes may complete out
  of order), so all replicas converge on the same last write per block.
  Overlapping writes from different attachments are ordered the same way,
  which gives multi-attach its single order per block (Requirement 4.2).
- **Commit.** `commit_seq` is the highest `seq` the primary has
  acknowledged; it rides on later `REPL_WRITE`s and on `PING`, and lets
  members trim their intent rings.
- **Reads** are served by the primary only, under its lease. The primary
  holds back a read that overlaps a write it has not yet acknowledged
  until that write completes, so a read never returns data that might
  still be rolled back. Reads from secondaries (to spread load) are a
  later option that needs read leases per member.
- **Checksums.** The initiator computes CRC32C over each block's
  ciphertext, so a flipped bit anywhere between oar-blk and the media is
  caught. hold verifies on receipt and on every read; a mismatch on read
  is repaired from another in-sync member (`SYNC_DATA` for that block)
  and counted; if no member has a good copy the read fails with IOERR and
  a `checksum_unrepairable` fault (Requirement 5.4).

## Epochs, leases and fencing

Three numbers fence everything:

1. **Epoch** — per volume, raised by the controller on every change of
   members, roles, attachments, size or class. Roles refuse lower epochs;
   a secondary that has applied epoch e+1 refuses `REPL_WRITE` from the
   primary of epoch e, so a deposed primary can never complete a write.
2. **Attachment generation** — retired when an attachment detaches, is
   forced off or is replaced; the primary refuses requests carrying a
   retired generation (`fenced`). This is what makes a partitioned compute
   server harmless: before a volume is attached elsewhere (or its VM is
   started elsewhere), the controller publishes a config without the old
   generation to the replica set (Requirement 6.9).
3. **Lease** — the primary may serve reads only while its lease is valid.
   hold sends a lease request through helm's report path every
   `lease_ms / 4`; the controller acknowledges it if this hold is still
   primary at the current epoch, and helm passes the acknowledgement
   down. The primary measures the lease from when it sent the request
   (monotonic clock), the controller from when it acknowledged; with a
   bounded clock-rate error (1 %) this is safe without synchronised
   clocks. The controller does not promote another replica until
   `lease_ms × 1.1` after its last acknowledgement, unless the old primary
   has sent `demotion_confirmed`. Default `lease_ms` = 4000.

The lease matters for reads: writes are already fenced by epochs, but a
partitioned old primary could otherwise serve stale reads to a
multi-attach reader that has not heard of the new epoch.

## Failure detection and failover

Detection is driven by the data path, with the controller's report
timeouts as a backstop:

| Signal | Detected by | Default |
|---|---|---|
| member not acking `REPL_WRITE` | primary | 2 s |
| primary not answering I/O or `PING` | initiator, members | 2 s |
| hold role silent in reports | controller | 10 s |
| lease renewal missing | controller | `lease_ms` |
| checksum or media error | any reader | immediate |

**Secondary lost.** The primary holds acknowledgements for writes the
member has not acked and sends `volume_fault {member_timeout}`. The
controller commits epoch e+1 without that member (or as `stale`), sends
it to the remaining members, and the primary acknowledges the held
writes. The primary starts a dirty-region bitmap (1 MiB regions) for the
lost member so it can be resynced partially. Typical pause: about 3 s.

**Primary lost.**

1. The initiator times out, keeps the guest's requests queued (the guest
   sees latency, not errors), and sends `volume_fault {primary_timeout}`.
2. The controller confirms (hold report silence or member reports) and
   waits out the old primary's lease.
3. It picks a new primary from the in-sync members of the latest epoch
   (preferring the one with the highest reported `seq`; all of them hold
   every acknowledged write), commits epoch e+1 and sends it to the
   members first, then to the attachments' servers.
4. **Reconcile.** Before serving, the new primary collects every member's
   uncommitted intent extents (`INTENTS`) and its own, and pushes its own
   copy of their union to every member. Writes that were never
   acknowledged may be lost or kept; both are allowed, and the
   initiator's retries (below) settle them.
5. The initiator receives the config, opens a session to the new primary
   and resends every request it has not seen acknowledged, in order. A
   resent write is idempotent because only one writer per block range is
   in flight per attachment.

Typical pause: 2 s detection + up to 4.4 s lease + about 1 s of commits
and reconcile, under the 10 s of Requirement 6.7.

**All members restart** (power loss). Every acknowledged write is durable
on every in-sync member. The controller re-admits the members of the
latest in-sync set, picks a primary, and the same reconcile runs.

**No in-sync member left.** The controller sets `io_suspended` and
`impaired`; initiators fail guest requests with IOERR after their deadline
(the oar-blk image-volume rule: never hang the guest). `EnableVolumeIO`
(Requirement 6.8) makes the most up-to-date surviving replica primary at
a new epoch and clears the flag, reporting the possible loss.

## Resync and rebuild

- **Partial resync.** A member back within `resync_window_s` (default
  15 min) gets only the regions in the primary's dirty bitmap for it plus
  the extents in its own intent ring. The bitmap lives in primary memory
  and is flushed to `meta` every few seconds; if the primary changed
  meanwhile the member falls back to a full rebuild.
- **Full rebuild.** The controller adds a `joining` member at epoch e+1.
  The primary forwards new writes to it at once and walks the volume's
  allocated regions (`SEEK_DATA`/`SEEK_HOLE`) in order, sending each
  region as `SYNC_DATA` on the same ordered stream as the forwarded writes.
  The region is read under a short region lock against new writes, so a
  forwarded write to a region always arrives after that region's copy
  and is never overwritten by older data. When the walk ends the joining
  member reports `in_sync` and the controller commits epoch e+2 with it as
  a secondary.
- **Pacing.** Rebuild and resync run in the lowest QoS class on both
  ends, with a per-role byte budget (default 40 % of the storage link)
  and a per-volume budget, yielding to tenant I/O (Requirement 7.4). At
  1 GB/s of spare disk and network a 1 TiB replica copies in about 18
  minutes, inside Requirement 7.6's hour with room for contention.
- **Ordering.** After a server loss the controller queues rebuilds by
  in-sync count (fewest first), then by volume class, and spreads target
  placement so no hold role receives more than a few concurrent rebuilds;
  since every volume's primary is a different source, a lost server's
  replicas are rebuilt many-to-many.

## Moving volumes

**Live move of a secondary** (Requirement 8): add the target as `joining`,
rebuild, promote it to secondary (epoch e+2), then remove the old member
(e+3). The replication factor never drops (Requirement 8.5).

**Live move of the primary**: after the target is in sync, a planned
handover:

1. The controller commits e+n marking the old primary `leaving` and the
   target as next primary.
2. The old primary stops admitting requests (answers `REDIRECT`), finishes
   in-flight writes and sends `demotion_confirmed`.
3. The controller commits the new primary at e+n+1 without waiting for
   the lease; the initiator follows the redirect. The pause is two
   controller commits and a drain, well under 1 s on a healthy cluster.

**Drain a storage server**: mark it `draining` in placement, then move
every replica off it, a bounded number at a time, and report empty.

**Unattached volumes** move the same way; the volume stays attachable
throughout because attachments only need the current primary.

**Local ↔ network conversion** (Requirement 8.6): a keyed copy on the
volume's server. oar-blk opens the local volume (its key from helm) and
the new network volume (its key from KMS via `VolumeKey`), and copies
decrypt-then-encrypt in a utility mode with no VM attached. The new
volume gets a new lineage.

**Between VMs and servers** (Requirement 9) needs no data movement:
detach, then attach anywhere. Changing the owning VM is a controller
record change (the network-volume `REWRAP_VOLUME`). A future VM live
migration attaches the volume on the destination as a second attachment
(allowed for that purpose even without `multi_attach`, read-only until
the handover), then the controller retires the source's generation and
makes the destination read-write in one epoch.

## Attach, hot-plug and cooperative detach

Attach follows the existing device-pool flow; what changes is
`prepare_function`:

| Step | Network volume |
|---|---|
| CREATE_VOLUME | no mailbox command: the controller places replicas and sends `ReplicaConfig` to the members, which create empty replicas |
| ATTACH_VOLUME (mailbox) | before relay: helm reserves a function and passes the ReplicaConfig to oar-blk, which opens a `NetworkVolumeBackend` and its session to the primary; after hull's ok: `VolumeKey` → `deliver_key` |
| DETACH_VOLUME | cooperative release (below), then hull's hot-unplug, function clean (key dropped); the controller retires the generation |
| DELETE_VOLUME | `delete_replica` on every member (trim, unlink); KMS key destroyed with the lineage's last member |

A VM may have up to 16 storage attachments (Requirement 3.1); each is its
own function, so the limit in practice is the number of functions a
server's oar-blk boards expose, which inventory already reports. Network
volumes and local volumes draw on the same pool.

### Detach blocked while mounted

Hot-unplug through the VMM (ACPI eject on Cloud Hypervisor) does not let
a Linux guest refuse: the kernel removes the device whether or not it is
mounted. Waiting for the guest therefore has to happen before hull asks
the VMM, and needs a signal the guest can see and an answer the host can
observe. Both live in `VirtioBlkFunction`, so the flow is the same for
local, image and network volumes:

1. **Request.** On `DETACH_VOLUME` with the new policy `wait` (now the
   controller's default), helm tells oar-blk `request_eject(function)`.
   The function sets `eject_requested` in a vendor-specific virtio PCI
   capability (`VIRTIO_PCI_CAP_VENDOR_CFG`, virtio 1.2) and raises a
   configuration-change interrupt. Standard drivers ignore the
   capability.
2. **Release.** The guest releases the disk through its normal removal
   path: on Linux, unmount and `echo 1 > /sys/bus/pci/devices/<bdf>/remove`,
   which makes the virtio driver reset the device; on Windows, "safely
   remove". The optional guest helper `ak-guest-eject` (a small daemon
   and udev rule shipped in `guest/`) polls the capability through sysfs,
   and when a detach is requested releases the disk if it has no mount,
   no holder (LVM, MD, dm-crypt), is not swap and is not open; otherwise
   it leaves it and logs why.
3. **Observe.** oar-blk reports `released` once the device status has been
   0 for 2 s with `eject_requested` set and the driver has not
   re-initialised it (a guest reboot resets and re-initialises, which is
   not a release).
4. **Unplug.** Only then does helm relay the detach to hull, whose VMM
   eject completes at once because the guest has already let go.
5. **Busy.** If no release arrives within the command's `timeout_s`,
   helm reports the attachment `busy`; it stays attached and serving, and
   the request stays pending until the guest releases, the controller
   cancels it, or a forced detach replaces it.

**Forced detach** (`force`): the controller first publishes a
ReplicaConfig without the attachment's generation and waits for the
primary to apply it (fencing, Requirement 3.5), then hull hot-unplugs
regardless, and the function is cleaned. The mailbox gets a third
`DetachPolicy`, `wait = 3`, beside `force` and `destroy_vm`; hull
Requirement 7.2 is amended to say that under `wait` it never ejects
before helm reports the release.

## Multi-attach

- Up to 16 attachments in one ReplicaConfig, any mix of servers, each
  `rw` or `ro`; more than one `rw` only with the volume's `multi_attach`
  flag (Requirement 4.6).
- Every attaching server gets its own `VolumeKey`; the primary orders all
  writes and serves all reads under its lease, which gives the single
  per-block order of Requirement 4.2.
- `ro` is enforced twice: the initiator offers `VIRTIO_BLK_F_RO` and fails
  writes, and hold refuses `WRITE` from a read-only generation.
- virtio-blk has no persistent reservations, so cluster software must
  fence through the API (forced detach). SCSI-3/NVMe reservations would
  need a virtio-scsi or NVMe function and are a later option; the EC2
  layer refuses reservation-dependent features.

## QoS and elasticity

- **Limits.** Token buckets per attachment-volume at the initiator (IOPS
  and bytes, I/O counted in 256 KiB units, Requirement 10.2) shape guest
  traffic; the primary enforces the same volume limits with 10 % slack
  and a weighted fair queue across volumes, so a compromised initiator
  cannot take more than its volume's share. Rebuild, hydration and scrub
  run in a lower class.
- **Classes** (controller policy, carried as numbers in the config):

  | Class | Replicas | Baseline | Max | Multi-attach | EBS analogue |
  |---|---|---|---|---|---|
  | `general` | 2 | 3000 IOPS, 125 MiB/s | 16 000 IOPS, 1000 MiB/s (hardware-dependent) | no | gp3 |
  | `provisioned` | 3 | as provisioned | 64 000 IOPS, 2000 MiB/s (hardware-dependent) | yes | io2 |

  The maxima are placeholders until harbor and the first board are
  measured; the mechanism does not depend on them.
- **Resize** (grow only): the controller raises `capacity_blocks` at a new
  epoch; members extend their files and checksum arrays first, then the
  initiator updates `virtio_blk_config.capacity`, bumps the config
  generation and raises the configuration-change interrupt, and the
  request parser's bound moves with it. Linux and Windows pick up the new
  size online.
- **Class or limit change**: a new epoch with new QoS numbers; a change of
  replica count adds or removes members as in "Moving volumes".

## Snapshots

### Format: image manifest version 2

Version 1 images keep one `data` object read with ranged GETs. Version 2
keeps the same header and digest list but stores each chunk as its own
object, named by its digest, so successive snapshots share unchanged
chunks:

```
<prefix>/lineage-<id>/chunks/<sha256 of chunk ciphertext>
<prefix>/lineage-<id>/snap-<manifest name>/manifest
```

New header fields in the version-2 manifest: flag `chunked`, the lineage
ID, the parent snapshot's manifest name (or zero), and the volume's block
size. Chunk size stays 1 MiB by default. The digest list is still the
manifest's integrity (the name is the manifest's SHA-256), so a fetched
chunk is checked exactly as today. Snapshots are always encrypted: the
chunks are the volume's ciphertext under the lineage key, with the LBA as
tweak, so a chunk is valid in place in any volume of the lineage.
Deduplication happens only within a lineage (the same key and offset give
the same ciphertext), which leaks nothing across tenants.

### Taking a snapshot

- **Cut.** A single-volume cut needs no pause: the primary picks the
  current `seq` S and tells members (`snapshot_prepare` / `commit`); the
  member that will upload (a secondary by default, to spare the primary)
  freezes when every write ≤ S is applied and before any > S: it pauses
  applying for the few milliseconds a `FICLONE` of `data` takes, copies
  and resets the changed-chunk bitmap, and resumes.
- **Multi-volume cut** (Requirement 11.2): the controller sends
  `snapshot_prepare` to every primary; each stops acknowledging new
  writes (it still accepts and persists them) and reports its S_i; on
  all reports the controller sends `snapshot_commit`, each primary
  releases its acknowledgements and the members freeze at S_i. Writes
  acknowledged before the prepare are in; none acknowledged after it
  are. The pause is one controller round trip, inside Requirement 11.9's
  100 ms on a healthy cluster; `snapshot_abort` releases on timeout.
- **Upload.** The uploader reads the frozen clone's changed chunks,
  hashes them, skips chunks whose digest object already exists (`HEAD`),
  `PUT`s the rest, then writes the manifest (unchanged chunk digests come
  from the parent manifest) and deletes the frozen clone. The snapshot is
  `completed` when the manifest is stored. hold's object-store
  credentials are write-only to its lineage prefixes (delivered by helm,
  like oar-blk's read credentials). This needs `PUT` and `HEAD` in
  `S3ObjectStore` (SigV4 with a payload hash).
- **Deletion and GC** (Requirement 11.8): the controller deletes the
  manifest, then mark-and-sweeps the lineage: any chunk object not named by
  a remaining manifest of the lineage is deleted. One sweep per lineage at
  a time; uploads of that lineage wait.

## Restore, hydration and clones

**Same-lineage restore** (a volume from one of its lineage's snapshots,
Requirement 11.4): the new volume's ReplicaConfig names the snapshot as
`source`. Replicas start empty with every chunk `unhydrated` (holes
count as hydrated). hold can hydrate on its own because the snapshot is
already ciphertext under the volume's key at the right offsets:

- a `READ` touching an unhydrated chunk makes the primary fetch it
  (the oar-blk `Fetcher` and `ChunkCache`, moved to a shared library),
  check its digest, compute block checksums, store it, replicate it
  (`HYDRATE_FILL`) and then serve the read;
- a `WRITE` into an unhydrated chunk hydrates that chunk first, then
  applies the write;
- a background walker hydrates the rest at `hydrate_mib_per_s` (EBS's
  provisioned initialization rate), sequentially from block 0 so boot
  regions arrive first; progress is reported.

**Fast restore** (Requirement 11.5): the controller keeps the volume in
`creating` until hydration completes (at a high rate), then marks it
`available`; reads never miss.

**Foreign-key restore** (public plaintext images, or a different
`KmsKeyId`, Requirements 11.7 and 12.5): hold cannot hydrate, because the
blocks must be re-encrypted under the new key. The volume's chunks start
`unhydrated` and hold answers reads of them with `not_hydrated`; oar-blk's
`HydratingBackend` (a persistent version of `LazyImageBackend`) fetches
the image chunk, decrypts it with K_img if needed, encrypts it with K_vol
and writes it with the `HYDRATE` flag, which fills only blocks the guest
has not written. It also hydrates in the background while attached. A
detached, partly hydrated volume resumes on its next attach; the
controller can also attach it to a utility function with no VM to finish
hydration (later task).

**Clones** (Requirement 11.6, EBS `CopyVolumes`): a cut as for a snapshot,
then each member `FICLONE`s its replica into a new replica directory for
the new volume ID on the same hold role. The clone is in the same lineage
(same key) and shares blocks copy-on-write; it can be moved elsewhere
later like any volume.

## Keys and crypto-erase

- One data key per **lineage** (volume, its snapshots, restores and
  clones). kythira KMS creates a non-exportable per-lineage KMS key and a
  data key wrapped under it; the controller stores only the wrapped blob.
  With a tenant `KmsKeyId` the per-lineage key is itself protected by the
  tenant key, so revoking the tenant key makes every volume of the
  lineage unattachable (details in the kythira spec).
- At attach the controller asks KMS to rewrap the data key to the
  attaching helm's secure-element public key (`VolumeKey`); KMS sees
  plaintext, the controller does not. helm's enrollment registers that
  public key with the controller.
- Delete of a volume trims and unlinks its replicas; when the lineage's
  last volume and snapshot are gone, the controller schedules the
  per-lineage KMS key for immediate deletion, which makes every remaining
  copy anywhere (backups of the controller's log, stray media)
  unreadable (Requirement 12.4). A per-lineage KMS key is what makes this
  hold even though copies of the wrapped blob survive in Raft snapshots.
- The local-volume key hierarchy (helm Requirement 4) is unchanged.

## Integrity (later)

XTS gives confidentiality, not integrity, and CRC32C catches accidents,
not adversaries. A hold role that rewrites or rolls back blocks causes
garbage or stale data, not disclosure. The later option: a per-block
HMAC-SHA-256 tag (16 bytes) under a key derived from the data key,
computed and checked by oar-blk and stored by hold beside the CRC; it
detects modification and relocation. Rollback detection needs a Merkle
root per volume kept by the controller and updated on commit, which costs
a controller round trip per flush; out of scope for now.

## Durability model

With independent failures, a two-replica volume is lost only if its second
replica fails during the rebuild window of the first:

```
P(loss per year) ≈ 2 λ · (λ · T_rebuild / 8760 h)
```

With a pessimistic per-replica failure rate λ = 4 %/year (drive, board
and server combined) and T_rebuild = 1 h, that is about 4 × 10⁻⁷, three
orders below the 0.1 % target (Requirement 5.3); three replicas add
another factor of λT. Real-world loss is dominated by correlated
failures (a rack's power, a firmware bug, a bad batch of drives) and by
software bugs, not by this term. The targets therefore rest on:
failure-domain placement (Requirement 5.2), rebuild within the hour
(7.6), scrubbing within 14 days so latent errors don't meet a rebuild
(5.5), checksums end to end (5.4), the simulation and harbor fault tests
(15), and, operationally, mixing drive batches and firmware across a
replica set.

## Controller reference model

The controller's volume state machine is specified by code: `src/hold/master/`
(`ak_hold_master`) implements placement, epoch and lease rules, failure
handling, rebuild queueing, moves, snapshot coordination and GC over an
abstract transport. It drives the simulation and harbor's test controller
(`ak-volctl`), and the kythira EC2 module ports it (or links it through a
C ABI) rather than re-deriving the rules from prose.

## Testing strategy

- Codecs: vectors and fuzz targets for `ReplicaConfig`, `VolumeOp`,
  `VolumeKey`, reports, the hold wire protocol, the replica `meta` header
  and manifest v2.
- `ReplicaStore`: crash-consistency tests that drop unsynced writes at
  every step (an in-memory file layer with crash injection).
- **Deterministic simulation** (`tests/hold_sim_test.cpp`): one thread, a
  simulated clock, network (loss, delay, reordering across connections,
  partitions) and disks (crash drops unsynced data), the real hold,
  initiator and master code, seeded. Each run records every guest
  operation and checks per-block linearizability (a register per block,
  Wing-Gong search), no acknowledged write lost, and no member serving
  after its lease. ctest runs a few hundred seeds; a nightly job runs
  many more.
- harbor (tikhov), Requirement 15.3, on a topology with two compute and
  three storage servers.

## Open questions

- The vendor ID for the virtio vendor capability (antikythera has no PCI
  vendor ID; harbor can use a placeholder).
- hold on a storage board vs a storage manager VM for dense servers
  (board throughput, about Gen3 x2, limits the former).
- How tenant `KmsKeyId` protects the per-lineage key (kythira KMS spec).
- Cross-AZ snapshot copy and regions, once kythira has more than one.
