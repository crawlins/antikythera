# Implementation Plan — hold: the fault-tolerant block volume service

## Status: 0/24 tasks complete

Tasks are in priority order: take the first open one whose prerequisites
are done. "cloud" tasks build and test in a cloud container; "tikhov"
tasks need nested KVM (harbor); "kythira" tasks land in the kythira
repository. Prerequisites outside this spec: oar-blk task 14
(asynchronous completion) is folded into task 3 here.

## Tasks

### Phase A: contracts

- [ ] 1. Protocol codecs in `src/proto/`: `ReplicaConfig`, `VolumeOp`,
  `VolumeKey`, and the report additions (`replica_status`,
  `volume_fault`, `attachment_status`, `demotion_confirmed`,
  `op_outcome`, `snapshot_progress`); signing test vectors under the
  RFC 8032 keys like `MapUpdate`; fuzz targets. helm verification of
  `ReplicaConfig` reuses the `MapUpdate` path. _Requirements: 6.1-6.2,
  12.2, 13.4_ (cloud)
- [ ] 2. hold wire protocol codec (`src/proto/hold_wire.*`): header,
  every opcode's payload, status codes, CRC32C helpers (portable table,
  SSE4.2 when available, no new dependency); `fuzz/fuzz_hold_wire.cpp`. _Requirements:
  13.4, 5.4_ (cloud)
- [ ] 3. Asynchronous `BlockBackend`: submit/complete interface,
  `VirtioBlkFunction` parks requests and completes them from backend
  callbacks (subsumes oar-blk task 14); the existing file, image and
  overlay backends adapted; fuzzing of the function kept. _Requirements:
  1.1, 2.2_ (cloud)
- [ ] 4. Controller reference model `src/hold/master/` (`ak_hold_master`):
  volume records, placement across failure domains, epoch, lease and
  attachment-generation rules, failure handling, rebuild queue, moves,
  snapshot coordination and GC, over an abstract transport; unit tests
  per rule. _Requirements: 5.2, 6, 7.1, 7.5, 8_ (cloud)

### Phase B: one replica, end to end

- [ ] 5. `ReplicaStore`: replica directory, `meta` header codec (fuzzed),
  data file with reflink detection, per-block CRC32C, chunk state,
  changed-chunk bitmap, intent ring, group commit, crash-injection tests
  over an in-memory file layer. _Requirements: 1.5, 5.4_ (cloud)
- [ ] 6. hold server, single replica: TLS 1.3 sessions with
  `server_id`-bound certificates, `HELLO` authorization against the
  ReplicaConfig, epoch and generation fencing, READ/WRITE/FLUSH, `ro`
  enforcement, per-volume QoS and fair queueing; `ak-hold` binary with a
  helm sideband stub. _Requirements: 1.5, 4.3, 6.2, 6.4, 10.2, 13_ (cloud)
- [ ] 7. `NetworkVolumeBackend` in oar-blk: session to the primary,
  CRC32C on writes and reads, QoS token buckets, request queue with
  deadlines, retry and `REDIRECT` handling across epochs, `await_route`
  beside `await_key`; tests against an in-process hold. _Requirements:
  1.1-1.3, 2.2, 6.6, 10.2_ (cloud)

### Phase C: fault tolerance

- [ ] 8. Replication: `seq` ordering, `REPL_WRITE`/`REPL_ACK` to every
  in-sync member, overlap ordering, `commit_seq`, intent trimming, read
  hold-back behind unacknowledged overlapping writes, checksum repair
  from a peer. _Requirements: 1.5-1.6, 4.2, 5.1, 5.4_ (cloud)
- [ ] 9. Deterministic simulation harness (`tests/hold_sim_test.cpp`):
  simulated clock, network and crashing disks around the real hold,
  initiator and master; per-block linearizability checker; seeded runs
  in ctest and a long nightly variant. _Requirements: 15.1_ (cloud)
- [ ] 10. Failover: config application in hold, leases through helm's
  report path, demotion, member-loss and primary-loss handling, intent
  reconcile on promotion, `io_suspended` and `EnableVolumeIO`; all
  exercised by the simulation. _Requirements: 6_ (cloud)
- [ ] 11. Resync and rebuild: dirty-region bitmaps, partial resync with
  returning members' intent extents, full sparse rebuild with `joining`
  members and region locks, pacing and priorities. _Requirements: 7_
  (cloud)

### Phase D: integration

- [ ] 12. helm integration: forward `ReplicaConfig`/`VolumeOp` to hold
  and oar-blk, relay reports, lease acknowledgement path, `VolumeKey`
  opened with HPKE in the secure element (software SE first), network
  volume attach in the CommandRouter, enrollment of the SE public key
  and role certificates. _Requirements: 9.3, 12.2-12.3, 13.1_ (cloud)
- [ ] 13. Cooperative detach for every volume kind: vendor virtio
  capability with `eject_requested`, release detection in
  `VirtioBlkFunction`, mailbox `DetachPolicy::wait`, `busy` reporting,
  forced detach after fencing; hull Requirement 7.2 amendment; the
  `guest/ak-guest-eject` helper with a udev rule and shellcheck.
  _Requirements: 3.3-3.6_ (cloud)
- [ ] 14. controller-interface and backplane spec updates: a
  management-fabric port on storage-capable data-plane slots, the storage
  VLAN and traffic classes (backplane), and EC2 mapping of
  Requirement 14 (`CreateVolume` types, `ModifyVolume`, snapshots,
  `CopyVolumes`, `EnableFastSnapshotRestores`, `EnableVolumeIO`, status
  checks, `busy`), replacing controller Requirement 6.2's server-local
  rule for network volumes. _Requirements: 13.5-13.6, 14_ (cloud, docs)
- [ ] 15. harbor: storage topology (two compute, three storage servers,
  storage VLAN on the management bridge, refused from helm
  addresses), `ak-volctl` test controller on `ak_hold_master`; boot
  a VM from a network volume, hot-plug several volumes into one VM, a
  mounted volume's detach stays `busy`, forced detach is fenced, stop and
  start on the other compute server. _Requirements: 2, 3, 9, 15.3_
  (tikhov)
- [ ] 16. harbor fault injection: kill the primary and a secondary under
  a write-verify workload, partition a compute server, rebuild, and
  check no acknowledged write is lost and only ciphertext is on every
  hold's media. _Requirements: 5, 6, 7, 15.3_ (tikhov)

### Phase E: movement and elasticity

- [ ] 17. Live moves: secondary move, planned primary handover with
  `demotion_confirmed`, drain of a storage server; simulation and harbor
  cases. _Requirements: 8.1-8.5_ (cloud, then tikhov)
- [ ] 18. Multi-attach: several attachments per config, `rw`/`ro` mix,
  per-server `VolumeKey`, harbor test with VMs on two servers writing
  disjoint and overlapping ranges. _Requirements: 4_ (cloud, then tikhov)
- [ ] 19. Elastic volumes: online grow with virtio-blk config-change
  interrupt and parser bound update, QoS and class changes, replica-count
  changes. _Requirements: 10.3-10.4_ (cloud)

### Phase F: snapshots and restore

- [ ] 20. Image manifest version 2 (chunked, lineage, parent) in the
  manifest codec; extract `Fetcher`, `ChunkCache`, `S3ObjectStore` into a
  shared library; S3 `PUT`/`HEAD` with payload-hash SigV4.
  _Requirements: 11.3_ (cloud)
- [ ] 21. Snapshots: single-volume cut, multi-volume prepare/commit cut,
  `FICLONE` freeze, incremental upload, deletion with lineage
  mark-and-sweep GC; tests against the loopback S3 emulator and
  SeaweedFS. _Requirements: 11.1-11.3, 11.8-11.9_ (cloud)
- [ ] 22. Same-lineage restore and clones: hold-side on-demand and
  background hydration at a set rate, fast restore, `FICLONE` clones.
  _Requirements: 2.3, 11.4-11.6_ (cloud)
- [ ] 23. Foreign-key restore: `HydratingBackend` in oar-blk for public
  images and re-keyed restores, `not_hydrated` and the `HYDRATE` write
  flag; local ↔ network conversion as a keyed copy. _Requirements: 8.6,
  11.7, 12.5_ (cloud)
- [ ] 24. Scrubbing: periodic full read and checksum verification per
  replica within 14 days, repair from peers, reporting.
  _Requirements: 5.5_ (cloud)

## Outside this repository

- kythira EC2 module: volume catalog and the ported master; kythira KMS
  per-lineage keys and HPKE rewrap to helm public keys (Requirement 12).

## Deferred

- Integrity tags and rollback detection (design "Integrity").
- Reads from secondaries; NVMe/TCP front; SPDK `ReplicaStore`; io_uring
  group commit.
- SCSI/NVMe persistent reservations for multi-attach clusters.
- VM live migration handover (needs hull live migration).
- HDD-backed throughput classes (st1/sc1), snapshot archive tier, recycle
  bin, cross-region snapshot copy.
