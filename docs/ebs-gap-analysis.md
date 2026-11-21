# Amazon EBS gap analysis

_Status as of 2026-11-21, against `main` (oar-blk tasks 1-6 and 9-11
merged). EBS facts are from AWS's public documentation as of late 2025._

## Goal

A tenant using the EC2 API through kythira should be able to run VMs from
block volumes that survive the loss of a server and can be moved between
servers, with the volume features they expect from EBS. This document
lists the volume options antikythera has today, maps each EBS feature onto
them, and says where the new [block-volume-service](../.kiro/specs/block-volume-service/)
spec closes the gap. Like [vpc-gap-analysis.md](vpc-gap-analysis.md) it
is a planning document; the requirements live in the spec.

## The volume options today

All three present an ordinary virtio-blk function from the oar-blk role,
encrypted with AES-256-XTS below the guest with a key only that role
holds (oar-blk Requirements 1-2).

| Option | What it is | State |
|---|---|---|
| **Local volume** | A sparse file (on hardware, an NVMe region) behind one server's oar-blk, with a wrapped key in its header. Persists across VM destroy unless `persist_volumes = false`, crypto-erased on delete, moves between VMs on the same server only with `REWRAP_VOLUME` | file backend and helm flows merged (#40 and earlier); boot from volume and harbor scenarios open (oar-blk 7-8) |
| **Image volume** | A read-only image in S3-compatible storage, fetched lazily in verified 1 MiB chunks into a shared cache, with the VM's writes in an ephemeral encrypted overlay discarded on detach | manifest, cache, fetcher, overlay, S3 client merged (#50 #53 #54 #58); `ak-image-pack`, helm wiring, async misses, encrypted images and harbor boot open (oar-blk 12-16) |
| **Self-encrypting NVMe** | Opal namespaces behind a storage manager VM | deferred |

None of them survives the loss of its server, none can be moved to
another server, and there are no snapshots, resize, or performance
classes. In EC2 terms, they are instance store, not EBS.

## Feature map

Status: **have** (built), **partial**, **spec** (in block-volume-service),
**later** (named in the spec as deferred), **no** (not planned).

| EBS feature | EBS | Today | Status | Where |
|---|---|---|---|---|
| Network-attached volumes, attach to any instance in the AZ | yes | local only | spec | Req 1, 9 |
| Boot from volume | yes | local volume (oar-blk 7), image volume (oar-blk 16) | spec | Req 2 |
| Root volume from AMI, usable before fully copied | lazy load from snapshot | image volume, but ephemeral | spec | Req 2.3, 11.4, 11.7 |
| Replication within the AZ | yes, transparent | none | spec | Req 5 (2 or 3 replicas, failure domains) |
| Durability | 99.8-99.9 % (gp2/gp3/io1), 99.999 % (io2) | server-bound | spec | Req 5.3: AFR ≤ 0.1 % / ≤ 0.001 % |
| Automatic failure detection, failover, rebuild | yes | none | spec | Req 6, 7 |
| Volume status checks, I/O suspended on inconsistency, `EnableVolumeIO` | yes | none | spec | Req 6.8, 14.2 |
| Detach and reattach to another instance | yes | same server only | spec | Req 9 |
| Stop/start instance on other hardware | yes | must return to the volume's server | spec | Req 2.4 |
| `DeleteOnTermination` | yes | `persist_volumes` per VM | spec | Req 9.4 (per volume) |
| Hot attach / detach | yes | device-pool flow, force or destroy-VM on timeout | spec | Req 3: cooperative detach, `busy` while mounted, forced detach fenced |
| Many volumes per instance | up to ~27 on Nitro (shared with ENIs) | one function each, limited by functions | spec | Req 3.1: at least 16 |
| Multi-Attach | io1/io2, up to 16 Nitro instances, same AZ | no | spec | Req 4 (16 attachments, any server, rw/ro) |
| NVMe reservations for Multi-Attach (io2) | yes | no | later | virtio-blk has none; needs virtio-scsi or NVMe |
| Volume types | gp3, gp2, io2 Block Express, io1, st1, sc1, standard | one kind | spec | Req 10.1: `general` (gp3-like), `provisioned` (io2-like); HDD classes later |
| Provisioned IOPS and throughput | gp3: 3000 IOPS/125 MiB/s baseline, up to 80 000 IOPS/2000 MiB/s; io2 BX up to 256 000 IOPS/4000 MiB/s | no limits | spec | Req 10.2 (limits enforced at initiator and hold) |
| Max volume size | 64 TiB (gp3, io2 BX) | 64 TiB mailbox limit | spec | Req 1.4: at least 16 TiB |
| Elastic Volumes (grow, change type/IOPS live) | yes, once per 6 h | no | spec | Req 10.3-10.4 |
| Encryption at rest | KMS, opt-in or account default | always on, per-VM key | have / spec | Req 12: KMS per-lineage data key, rewrapped to each helm |
| Encryption in transit | Nitro, in hardware | n/a | spec | Req 1.2 (ciphertext only), 13.1 (mTLS) |
| Guest holds no key | yes | yes | have | oar-blk Req 2 |
| Snapshots, incremental, in S3 | yes | none | spec | Req 11.1-11.3 (image manifest v2, per-chunk objects) |
| Crash-consistent multi-volume snapshots | `CreateSnapshots` | none | spec | Req 11.2 |
| Fast snapshot restore | yes | none | spec | Req 11.5 |
| Provisioned rate for volume initialization | 100-300 MiB/s | none | spec | Req 11.4 (`hydrate_mib_per_s`) |
| Volume clones (`CopyVolumes`) | yes (2025) | none | spec | Req 11.6 (reflink, same lineage) |
| Live move between storage servers | internal to AWS | none | spec | Req 8 (live, planned primary handover, drain) |
| Move across AZ/region | via snapshot copy | none | no (one region) | |
| EBS direct APIs (read snapshot blocks) | yes | none | no | |
| Snapshot archive tier, Recycle Bin, Data Lifecycle Manager | yes | none | later / kythira | controller policy over Req 11 |
| CloudWatch volume metrics | yes | counters in image backend | spec | Req 10.5 |
| Instance store (ephemeral, local NVMe) | yes | local and image volumes | have | oar-blk |

## Where antikythera differs on purpose

- **Encryption is always on and below the guest**, with the key only in
  the compute server's oar-blk; storage servers hold ciphertext. EBS
  encrypts in the Nitro card too, but lets volumes be unencrypted.
- **Detach waits for the guest by default.** EBS lets a detach proceed
  (and can stick in `busy`); here a mounted volume is never pulled unless
  the caller forces it, and a forced detach fences the attachment first.
- **Multi-attach across servers and with any mix of read-only and
  read-write attachments**, but without NVMe reservations at first.
- **The controller's volume rules ship as code** (a reference model used
  by tests and ported by kythira) instead of only prose.
