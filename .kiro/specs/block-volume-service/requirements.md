# Requirements Document — hold: the fault-tolerant block volume service

## Introduction

Today every antikythera volume lives on one server: a local volume is a
file (or later a namespace) behind that server's oar-blk role, and an
image volume is a read-only S3 image under a throwaway overlay. A server
that dies takes its local volumes with it, a VM can only run where its
volumes are, and nothing can move a volume to another server.

This spec adds **network volumes**, the antikythera counterpart of Amazon
EBS. A network volume is stored on a replica set of **hold** roles on
storage servers and reached by a VM through the ordinary oar-blk
virtio-blk function on whichever server the VM runs on. The guest still
sees a plain virtio-blk disk, still holds no key, and can boot from it.
The service survives the loss of a replica, detects failures and rebuilds
lost redundancy on its own, and moves volumes between storage servers
while they are in use. A VM can have many volumes, plugged and unplugged
while it runs, and a volume can be attached to several VMs at once.

The existing local and image volumes stay: they remain the fastest
options and become the equivalent of EC2 instance store. `docs/ebs-gap-analysis.md`
maps every EBS feature onto the three volume kinds and says which ones
this spec builds.

### What this spec does not cover

- Live migration of a running VM between compute servers. hull does not
  migrate VMs yet; this spec only provides the attachment handover such a
  feature will need (Requirement 9.5).
- Cross-region replication and cross-region snapshot copy.
- Authenticated (tamper-evident) storage against a malicious storage
  server. The service gives confidentiality and detects media
  corruption; it does not detect a hold role that deliberately rolls a
  block back. Design "Integrity" describes the later option.
- The kythira EC2 module's implementation. This spec defines the
  contract and ships a reference implementation of the controller's
  volume state machine for tests; the module itself is a kythira spec.

## Glossary

- **Network volume** — a block device whose data lives on a replica set
  of hold roles, attachable from any compute server in the region.
- **hold** — the storage-server data-plane role that stores replicas.
  Like every oar it is untrusted and contained: it sees only ciphertext.
- **Initiator** — the oar-blk role on the compute server that serves the
  guest's virtio-blk function and talks to the replica set.
- **Replica** — one full copy of a volume's ciphertext on one hold role.
- **Replica set** — the replicas of one volume: one **primary**, which
  orders and serves all I/O, and one or more **secondaries**.
- **In-sync** — a replica that holds every write acknowledged in the
  current epoch.
- **Epoch** — a number the controller raises on every change to a
  volume's replica set or attachments. Every request carries it; a role
  refuses a lower one.
- **ReplicaConfig** — the controller's signed, full description of one
  volume at one epoch: members and their roles, attachments, size, class.
- **Attachment** — one volume presented to one VM through one oar-blk
  function, identified by an attachment ID and a generation.
- **Lineage** — a volume, the snapshots taken from it, and the volumes
  and clones made from those snapshots; all share one data key.
- **Snapshot** — a point-in-time copy of a volume in object storage, in
  the image format of oar-blk Requirement 8, stored incrementally.
- **Hydration** — filling a volume made from a snapshot or image with
  that source's blocks, on demand or in the background.
- **Volume class** — the durability and performance tier of a volume
  (replication factor, IOPS and throughput limits, multi-attach).

## Requirements

### Requirement 1: Network volumes for guests

**User Story:** As a tenant, I want to run VMs from block volumes that live
on the storage service, so that a VM is not tied to the server its disks
were created on.

#### Acceptance Criteria

1. A network volume SHALL be presented to the guest as an ordinary
   oar-blk virtio-blk function (oar-blk Requirement 1), indistinguishable
   to the guest from a local volume except in performance.
2. The initiator SHALL encrypt every write and decrypt every read with
   AES-256-XTS under the volume key, as for local volumes (oar-blk
   Requirement 2); hold roles, the storage network and object storage
   SHALL see only ciphertext.
3. A network volume SHALL be attachable from any compute server in the
   region whose initiator can reach the volume's replica set.
4. Volume sizes SHALL range from 1 GiB to at least 16 TiB in 1 GiB
   steps, with a logical block size of 512 bytes or 4 KiB chosen at
   creation.
5. Every write SHALL be acknowledged to the guest only after it is on
   persistent media on every in-sync replica, so that FLUSH and FUA are
   satisfied by every completed write.
6. Reads SHALL return the most recently acknowledged write to each block
   (per-block linearizability), across failover and migration.

### Requirement 2: Booting from a network volume

**User Story:** As a tenant, I want to boot a VM from a network volume,
including a root volume freshly made from an image, without waiting for
the image to be copied.

#### Acceptance Criteria

1. A VM SHALL be bootable from an attached network volume through the
   guest firmware's virtio-blk support, with no host-supplied image.
2. The initiator SHALL hold guest requests, without failing them, until
   both the key and the replica set route have arrived (extending
   `await_key`).
3. A root volume made from a snapshot or an image SHALL be bootable as
   soon as it is created; blocks not yet hydrated SHALL be fetched on
   demand (Requirement 11.4).
4. WHEN a VM is stopped and started THEN it SHALL be able to start on any
   compute server with capacity, re-attaching its network volumes there.

### Requirement 3: Many volumes per VM and hot-plug

**User Story:** As a tenant, I want to give a VM several disks and add or
remove them while it runs, without risking a disk that is still mounted.

#### Acceptance Criteria

1. A VM SHALL be able to have at least 16 volumes attached at once, of
   any mix of local, image and network volumes, each on its own oar-blk
   function; the controller SHALL refuse an attach beyond the server's
   free functions or the VM's limit with a clear error.
2. Volumes SHALL be attachable to a running VM by PCIe hot-plug, and the
   guest SHALL see the new disk without a reboot.
3. Detach SHALL be cooperative by default: a volume SHALL NOT be removed
   from a running VM until the guest has released it (its driver has let
   go of the device). A volume the guest still holds SHALL stay attached,
   with the detach reported as `busy` (EC2's `busy` attachment state),
   and SHALL keep serving I/O.
4. The guest SHALL be able to release a volume through its normal device
   removal path; antikythera SHALL ship a small optional guest helper that
   releases an unmounted volume when a detach is requested and refuses
   while it is mounted or open.
5. A forced detach SHALL remove the volume whether or not the guest
   released it, after fencing the attachment so that no request from it
   can reach the volume afterwards (Requirement 6.4).
6. A detach SHALL NOT be reported complete until every request the
   attachment issued has completed or been fenced.

### Requirement 4: Multi-attach

**User Story:** As a tenant running a clustered application, I want
several VMs, on the same or different servers, to use one volume at once.

#### Acceptance Criteria

1. A volume of a class that allows it SHALL be attachable to at least 16
   VMs at once, on any compute servers, each attachment read-write or
   read-only.
2. Concurrent attachments SHALL see a single order of writes per block:
   a read issued after a write completed on any attachment SHALL return
   that write or a later one.
3. A read-only attachment's writes SHALL fail with an I/O error at the
   initiator and SHALL be refused by the hold role as well.
4. Every attachment SHALL receive the volume key from its own server's
   helm; the controller SHALL deliver no key to a server without a
   current attachment.
5. Detaching or fencing one attachment SHALL NOT disturb the others.
6. Multi-attach SHALL NOT be offered as safe for ordinary file systems:
   the API SHALL require an explicit opt-in on the volume, as EC2 does.

### Requirement 5: Replication and durability

**User Story:** As a tenant, I want my volume to survive the loss of a
disk, a storage board or a whole storage server without losing an
acknowledged write.

#### Acceptance Criteria

1. Every network volume SHALL be stored on at least two replicas on
   different storage servers; a class MAY require three.
2. The controller SHALL place a volume's replicas in different failure
   domains (server, and rack or power domain when the inventory reports
   them) and SHALL refuse a placement that cannot honour this.
3. The service SHALL target an annual failure rate of at most 0.1 % for
   two-replica classes and at most 0.001 % for three-replica classes,
   and the design SHALL state the rebuild-time assumption behind each
   target.
4. Every block SHALL carry a checksum of its ciphertext, computed by the
   initiator, stored with the replica and verified on every read by the
   hold role and the initiator; a mismatch SHALL be repaired from another
   in-sync replica, never returned to the guest.
5. Every replica SHALL be scrubbed (read in full and its checksums
   verified) at least every 14 days.

### Requirement 6: Failure detection and failover

**User Story:** As a tenant, I want a storage failure to cost my VM a short
I/O pause, never a split brain or a silent rollback.

#### Acceptance Criteria

1. The controller SHALL be the only authority over a volume's replica
   set; no hold role or initiator SHALL promote, demote or add a replica
   on its own.
2. Every data-path request SHALL carry the volume epoch; a role SHALL
   refuse a request with a lower epoch than the newest it has applied,
   and a replica SHALL refuse writes from a primary of a superseded epoch.
3. A primary SHALL serve reads only while it holds a lease; the
   controller SHALL NOT promote another replica until the old primary's
   lease has expired or the old primary has confirmed its demotion.
4. Every attachment SHALL carry a generation; WHEN an attachment is
   detached, forced off, or replaced THEN its generation SHALL be retired
   and the hold role SHALL refuse every request carrying it.
5. WHEN a secondary stops acknowledging writes within its deadline THEN
   the primary SHALL report it and the controller SHALL remove it from
   the in-sync set at a new epoch, after which writes continue.
6. WHEN the primary stops answering THEN the initiator SHALL report it
   and the controller SHALL promote an in-sync secondary at a new epoch;
   unacknowledged requests SHALL be retried against the new primary.
7. A single failure of a replica SHALL pause a volume's I/O for at most
   10 seconds in the reference configuration.
8. IF no in-sync replica of a volume survives THEN the controller SHALL
   mark the volume `impaired` and suspend its I/O; the service SHALL NOT
   serve data from a replica that was not in-sync. Only an explicit
   operator or tenant action SHALL resume I/O from the best surviving
   replica, accepting possible loss of recent writes.
9. A compute server partitioned from the controller SHALL NOT be able to
   write to a volume that has since been attached elsewhere.

### Requirement 7: Rebuild of lost redundancy

**User Story:** As the operator, I want lost replicas rebuilt without my
intervention and without starving tenant I/O.

#### Acceptance Criteria

1. WHEN a replica leaves the in-sync set THEN the controller SHALL start
   restoring the volume's replication factor, on the same server if it
   returns within the resync window, otherwise on a new server.
2. A replica that returns within the resync window SHALL be brought back
   by copying only the regions written while it was away.
3. A new replica SHALL be built by copying only the allocated regions
   while the volume stays in use; it SHALL join the in-sync set only once
   it holds every acknowledged write.
4. Rebuild traffic SHALL be rate-limited per hold role and per volume and
   SHALL yield to tenant I/O.
5. The controller SHALL rebuild volumes with the fewest in-sync replicas
   first, and SHALL spread the rebuilds after a server loss across many
   source and target servers.
6. The design SHALL bring a 1 TiB replica back to in-sync within one hour
   on the reference hardware when the network and disks are otherwise
   idle.

### Requirement 8: Moving volumes between storage servers

**User Story:** As the operator, I want to move a volume from one storage
server to another, while it is attached or not, to balance load or empty
a server for maintenance.

#### Acceptance Criteria

1. A volume SHALL be movable to another storage server while attached,
   with no I/O error seen by the guest.
2. Moving the primary SHALL be a planned handover: the old primary
   drains, confirms its demotion and the new one takes over, pausing I/O
   for at most 1 second in the reference configuration.
3. Moving an unattached volume SHALL use the same mechanism and SHALL
   leave the volume attachable throughout.
4. A storage server SHALL be drainable: the controller moves every
   replica off it, keeping each volume's replication factor throughout,
   and reports when the server is empty.
5. A move SHALL never lower a volume's in-sync replica count below its
   replication factor: the new replica joins before the old one leaves.
6. A local volume SHALL be convertible into a network volume, and back,
   while detached.

### Requirement 9: Moving volumes between VMs and compute servers

#### Acceptance Criteria

1. A detached network volume SHALL be attachable to any VM on any
   compute server in the region.
2. A volume SHALL change owning VM only through `REWRAP_VOLUME`'s
   equivalent for network volumes, which changes the owner recorded by
   the controller; the data key does not change.
3. The volume key SHALL reach a compute server's helm only for the
   duration of an attachment on that server.
4. `TerminateInstances` with `DeleteOnTermination` SHALL delete the
   instance's network volumes; otherwise they SHALL remain, detached.
5. The design SHALL let a future VM live migration attach a volume on the
   destination before detaching it on the source, with the source's
   attachment fenced at the handover.

### Requirement 10: Volume classes, performance and elasticity

**User Story:** As a tenant, I want to choose and later change how fast and
how durable a volume is, and grow it, without detaching it.

#### Acceptance Criteria

1. The service SHALL offer volume classes covering at least a general
   purpose class (two replicas, baseline and provisionable IOPS and
   throughput, like gp3) and a provisioned-IOPS class (three replicas,
   higher limits, multi-attach, like io2).
2. Each volume SHALL have IOPS and throughput limits, enforced at the
   initiator and again at the hold role (an initiator is untrusted).
   I/O SHALL be counted in units of up to 256 KiB.
3. A volume SHALL be growable while attached; the guest SHALL see the new
   capacity through virtio-blk's configuration-change notification.
   Shrinking SHALL be refused.
4. A volume's class, IOPS and throughput SHALL be changeable while
   attached; a change of replication factor SHALL add or remove replicas
   through Requirements 7 and 8.
5. The service SHALL report per volume: read and write operations,
   bytes, latency histograms, time throttled, and queue depth.

### Requirement 11: Snapshots, restore and clones

**User Story:** As a tenant, I want point-in-time snapshots of my volumes,
and volumes made from them that are usable at once.

#### Acceptance Criteria

1. A snapshot SHALL be crash-consistent: it SHALL contain every write
   acknowledged before its cut and no write issued after it; writes in
   flight at the cut MAY be in or out, as after a crash.
2. A snapshot of several volumes SHALL be takable with one cut across
   all of them.
3. Snapshots SHALL be stored in S3-compatible object storage in the image
   format (oar-blk Requirement 8), extended so that a snapshot stores
   only the chunks changed since the previous snapshot of its lineage.
4. A volume made from a snapshot SHALL be usable immediately, hydrating
   blocks on first read and the rest in the background at a configurable
   rate.
5. A snapshot SHALL be restorable fully hydrated before first use (the
   equivalent of fast snapshot restore).
6. A volume SHALL be clonable to a new volume of the same lineage in
   seconds, without copying its data first.
7. A root volume SHALL be creatable from a public (plaintext) image; its
   blocks SHALL be encrypted under the new volume's key as they are
   hydrated.
8. Deleting a snapshot SHALL free the chunks no other snapshot uses.
9. Snapshot taking SHALL NOT pause guest I/O for more than 100 ms.

### Requirement 12: Keys and crypto-erase for network volumes

**User Story:** As a tenant, I want network volumes encrypted with keys that
no storage server ever sees, and destroyed when I delete the volume.

#### Acceptance Criteria

1. Each lineage SHALL have its own data key, generated by and stored
   wrapped in kythira KMS, optionally under a tenant `KmsKeyId`.
2. The controller SHALL deliver a data key to a compute server only
   wrapped to that server's helm (its secure-element public key), and
   helm SHALL unwrap it inside the secure element and deliver it only to
   the oar-blk role serving the attachment, over its own sideband.
3. No hold role, mailbox message or host-visible memory SHALL carry key
   material.
4. Deleting a volume SHALL destroy its replicas (trim and release); the
   data key SHALL be destroyed in KMS when the last member of its
   lineage is deleted, crypto-erasing every copy anywhere.
5. Creating a volume from a snapshot with a different `KmsKeyId` SHALL
   start a new lineage with a new data key (a keyed copy).

### Requirement 13: Storage traffic on the management fabric, and hold isolation

#### Acceptance Criteria

1. Initiators and hold roles SHALL talk over the management fabric, never
   the tenant VPC fabric, authenticated and encrypted in transit with
   per-role identities issued at enrollment.
2. A hold role SHALL accept a data-path session for a volume only from a
   member of the volume's replica set or from a server holding a current
   attachment to it, as the latest ReplicaConfig says.
3. A hold role SHALL see no key, no plaintext and no tenant identity
   beyond opaque volume and attachment IDs.
4. Every parser of storage-network traffic, ReplicaConfig and volume
   operation frames SHALL return `std::expected`, use `ak::wire`, and have
   unit tests and a fuzz target.
5. Storage traffic SHALL be kept on its own segment of the management
   fabric, apart from helm's controller link, so that a data-plane role
   cannot reach the controller or another server's helm.
6. Storage traffic SHALL NOT be able to starve control traffic: the
   controller link and lease traffic SHALL have priority over storage
   I/O on the fabric, and storage I/O SHALL have priority over rebuild,
   hydration and scrub.

### Requirement 14: EC2 API mapping

#### Acceptance Criteria

1. The controller-interface spec SHALL map these EC2 actions onto this
   service: `CreateVolume` (`VolumeType`, `Size`, `Iops`, `Throughput`,
   `SnapshotId`, `MultiAttachEnabled`, `Encrypted`, `KmsKeyId`),
   `DeleteVolume`, `AttachVolume`, `DetachVolume` (`Force`),
   `ModifyVolume`, `DescribeVolumes`, `DescribeVolumeStatus`,
   `EnableVolumeIO`, `CreateSnapshot`, `CreateSnapshots`,
   `DeleteSnapshot`, `DescribeSnapshots`, `EnableFastSnapshotRestores`,
   `CopyVolumes`, and `RunInstances` block device mappings with
   `DeleteOnTermination`.
2. Volumes SHALL report EC2's states (`creating`, `available`, `in-use`,
   `deleting`, `deleted`, `error`), attachment states (`attaching`,
   `attached`, `detaching`, `detached`, `busy`) and volume status checks
   (`ok`, `impaired`, `warning`, `insufficient-data`).
3. EBS features this service does not back SHALL be refused with
   `UnsupportedOperation`, never silently accepted.

### Requirement 15: Testing

#### Acceptance Criteria

1. A deterministic in-process simulation SHALL run the controller
   reference model, hold roles and initiators under crashes, partitions,
   message loss and delay, and check every history against
   Requirements 1.6 and 6 with a linearizability checker.
2. Unit tests and fuzz targets SHALL cover every codec of Requirement 13.4.
3. harbor SHALL verify on a multi-server topology: boot from a network
   volume, several volumes hot-plugged into one VM, a mounted volume's
   detach reported `busy` and a forced detach fenced, multi-attach from
   VMs on two servers, kill of the primary and of a secondary under load
   with no acknowledged write lost, rebuild, live move of the primary,
   stop/start of a VM on another server, and only ciphertext on every
   hold role's media.
