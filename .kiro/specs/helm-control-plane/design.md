# Design Document — helm: the control-plane role

## Overview

helm is an event loop around four pieces of state — the device pool, the
key store, the mapping table and the slot table — driven by three
channels: controller (inbound signed commands), mailbox (to hull), and
sideband (to each oar). Nothing else can change that state.

```
            controller (kythira EC2 module)
                   │  signed envelopes, MAP_UPDATE, status
                   ▼
┌──────────────────────────── helm ─────────────────────────────┐
│  ControllerLink ──► CommandRouter ──► DevicePool  KeyStore    │
│                         │              MappingTable SlotTable │
│        MailboxDevice ◄──┘                    │                │
│        (BAR0 slots, MSI)         OarLink[slot] (MCTP)         │
│        PowerSequencer ── PERST#/power/link-ready per slot     │
└───────────┬──────────────────────────────────┬────────────────┘
            │ PCIe (no DMA)                    │ isolated sideband segments
            ▼                                  ▼
          hull                        oar-net / oar-blk / oar-gpu
```

## Components

### MailboxDevice

Implements the BAR0 register file (`src/helm/mailbox.hpp`, already
written). In harbor it is a vfio-user server; on hardware, a `pci-epf`
function (or FPGA logic). It owns the slot buffers and doorbells and raises
MSI-X vector 0 for commands. It never initiates DMA.

### CommandRouter

Takes a verified-by-shape controller envelope, checks the sequence number,
and turns it into: device-pool reservations, oar requests (prepare the
function), then a mailbox command to hull, then pool commits on hull's
response. Each step is idempotent on retry by sequence number.

Built in `src/helm/command_router.*`. Decisions made in the implementation:

- Retries. A sequence number at or below the highest accepted is never
  relayed. A retry of a finished command gets its recorded outcome
  reported again; a retry of one still queued or in flight is ignored;
  anything else is `stale_sequence`.
- One command in the mailbox at a time (Requirement 1.5); the rest wait
  in a bounded queue, and a full queue refuses with
  `insufficient_resources` without consuming the sequence number.
- Creative steps before relay, destructive steps after hull's ok.
  Reserving a function, preparing it on its role, creating a VM or volume
  key and storing a new volume (with its wrapped key) on the storage role
  happen before the slot goes to the mailbox, each with a compensation.
  Releasing functions, destroying keys (`DELETE_VOLUME`, `DESTROY_VM`
  without `persist_volumes`) and erasing those volumes on the media, and
  `REWRAP_VOLUME` (KeyStore, then the volume header) wait for hull's
  `ok`/`accepted`, which means hull has verified the controller's
  signature: a forged or replayed envelope can never crypto-erase
  anything. A media step that fails after commit is counted
  (`storage_failures`); it cannot be undone.
- `ATTACH_VOLUME` delivers the volume key after hull's `ok`, not before
  relay: hull answers once the VMM has opened the function, and that open
  resets it (FLR), which wipes a key delivered earlier. The function holds
  the guest's I/O until the key arrives. A failed delivery is audited
  (`volume_key_delivery_failed`) and reported as a `device_lost` host
  fault naming the slot and volume.
- helm checks preconditions it owns before relaying (volume owner and
  attachment, function type and state, `REWRAP_VOLUME`'s `from_vm`) and
  answers a violation itself. Malformed slots are refused as `malformed`,
  `GPU_VF_CONFIG` as `unsupported`.
- A failed attach (role refused, hull answered with an error, mailbox
  write failed) moves the function
  `assigned → cleaning` (pool event `attach_failed`): hull never handed
  it to the VM, but the role may hold the VM's configuration or key.
- Timeouts report `timed_out` and do nothing else: reservations stay
  held, since hull may have applied the command, and destructive steps
  never run. A late response is audited and dropped.
- hull is the authority on what a VM holds: a `DEVICE_RELEASED` for a
  function still `assigned` to that VM (the event overtook the
  `DESTROY_VM` response) releases it first.
- Cleaning: NIC and storage functions are cleaned synchronously over the
  sideband; GPU functions wait for `SCRUB_DONE`. A function waiting in
  `releasing` or GPU `cleaning` past its timeout is faulted.
- ATTACH_DEVICE for a NIC VF carries its VPC (VNI), NIC ID and MAC in the
  signed command (mailbox v3), and the router prepares the VF on oar-net
  with exactly those; helm holds no network identity of its own.

### Audit log

`src/helm/audit_log.*`. One ASCII line per record, fields in a fixed
order (`n= t= ev= [seq=] [cmd=] [status=] [vm=] [vol=] [fn=] [count=]
h=`), where `h` is SHA-256 over the previous record's `h` and this line
up to ` h=`. The file is opened `O_APPEND`, created `0600`, and refused
if it is a symlink, not a regular file, group/other accessible, or does
not verify; a restart continues the same chain. The record type has no
field that can hold key material, only IDs. The router audits every
accepted, refused, relayed, answered and timed-out command and every key
operation, and does not relay a command whose relay record could not be
written. `verify_audit_log` is strict (canonical form, consecutive
indices, every hash) and fuzzed.

### DevicePool

```
           assign                 VM release / detach
 free ───────────────► assigned ───────────────────► releasing
  ▲                                                     │ hull: DEVICE_RELEASED
  │  oar: clean ok (NIC, blk) / SCRUB_DONE (GPU)        ▼
  └──────────────────────────────────────────────── cleaning ◄────────┐
                                                        │ error /      │ slot power-cycle ok
                                                        ▼ timeout      │
            releasing: reset failed / timeout ──────► faulted ─────────┘
```

Types: `nic_vf`, `blk_fn`, `gpu_whole`, `gpu_vf`. Cleaning action by type:
NIC → dead VPC + clear queues/MAC; blk → drop key from memory; GPU →
scrub VRAM (manager VM or scrubber VM). Implemented as a table-driven state
machine (`src/helm/device_pool.hpp`, `transition_table`) so illegal
transitions are refused without side effects and testable exhaustively.

Decisions made in the implementation:

- GPU functions leave `cleaning` only on `SCRUB_DONE`; NIC and blk
  functions only on the role's clean confirmation.
- A power-cycled `faulted` function returns to `cleaning`, not `free`: a
  power cycle does not guarantee a wipe (VRAM in particular).
- A function added from a role's inventory starts in `cleaning`, since helm
  cannot know what a previous boot left in it.
- A function stays owned by its VM through `releasing`, until hull confirms
  the reset; only the owning VM can release it.

### KeyStore

Wraps the secure element. API: `create_vm_key`, `destroy_vm_key`,
`create_volume_key(vm)`, `unwrap_volume_key(vol) → ScopedKey`,
`rewrap(vol, new_vm)`, `destroy_volume_key`, and
`create_ephemeral_key() → ScopedKey` (a fresh key for one attachment of
an image volume, never wrapped or kept; oar-blk-data-plane design).
`ScopedKey` is a move-only
type whose destructor zeroizes (`OPENSSL_cleanse`) and which can only be
consumed by `OarLink::deliver_key`. In harbor the secure element is a
file-backed software implementation behind the same interface.

The secure element interface takes and returns only wrapped keys, so a
plaintext VM key never leaves it; the only plaintext out is a volume key
(or an ephemeral key) as a `ScopedKey`. Wrapping is AES-256-GCM with a random 96-bit nonce,
and the AAD binds the blob's header and identity (`vm_id` for a VM key,
`volume_id` and owner `vm_id` for a volume key): a wrapped volume key
copied to another volume, or presented as another VM's, fails
authentication, which is what makes `REWRAP_VOLUME` the only way to move
a volume (Requirement 4.7). Wrapped keys have a versioned wire format
(`version | kind | key_len | nonce | ciphertext | tag`), decoded as
untrusted input since volume keys come back from the media.
`destroy_vm_key` also drops every volume key the VM key wraps and
returns those volumes, crypto-erased. The software secure element keeps
its 32-byte master key in a file created `0600` and refuses a symlink, a
non-regular file, group/other permission bits, or the wrong size.

### OarLink

One per data-plane role. MCTP message types (vendor-defined) for:
`function_inventory`, `prepare_function`, `clean_function`,
`deliver_key`, `drop_key`, `map_update`, `group_policy`, `group_usage`,
`health`. Transport binding:
`SmbusBinding` (hardware), `I3cBinding` (later), `SocketBinding` (harbor,
one Unix socket per slot), `InProcessBinding` (combined placement).

Every binding carries the same encoded SMBus packets (with PEC) that the
wire does, one packet per send: `SocketBinding` is an `AF_UNIX`
`SOCK_SEQPACKET` socket, whose datagram boundaries are packet boundaries,
and `InProcessBinding` a pair of bounded queues. So the MCTP codec and
reassembly run unchanged in every placement and only the binding differs
(Requirement 7.1). Message bodies are in `src/helm/oar_protocol.hpp`:
little-endian, strict both ways, with a 2-byte status head on every
response. helm owns the MCTP tags and has one request outstanding per
link; a response that arrives after its request timed out carries an old
tag and is discarded, never taken for the next answer. Malformed or
misaddressed packets are dropped and counted rather than failing the
request, so noise costs time, not correctness.

`map_update` forwards the controller's MapUpdate frame unmodified,
signature included, so the role can check it itself. A frame (up to
131 KiB) exceeds the 4 KiB MCTP message bound, so it travels as
consecutive chunks (`total`, `offset`, bytes); offset 0 restarts a
transfer, any gap or changed total aborts it, and the last chunk's answer
is the result of applying the frame.

`group_policy` forwards the controller's GroupPolicy frame the same way
(it fits one message). `group_usage` asks a network role for its per-NIC
group meters; the answer is the `group_usage` report body, which helm
wraps in a report header and sends (Requirement 11). The role keeps a
detached NIC's final meter until it has answered one `group_usage`; helm
then keeps it until the controller acknowledges that report.

`create_volume`, `delete_volume` and `rewrap_volume` are the storage
role's half of the volume commands: the role keeps the wrapped key (opaque
to it) in the volume's metadata and releases the space on delete. Other
roles answer `unsupported` (OarHandler's defaults).

`deliver_key` is the one place a plaintext volume key leaves helm.
`OarLink` takes the `ScopedKey` by value, encodes it into exactly-sized
buffers, and wipes the body, message and every packet after sending,
success or failure. `OarEndpoint` wipes the reassembled request once the
role's handler returns, so the handler must copy the key into its key slot
during the call. Bytes in flight inside a binding (the kernel socket
buffer, a queue entry) are outside this layer.

### PowerSequencer

Per-slot PERST#, power enable, link-ready input; host PERST#/power. Boot
order: slots up → link-ready or timeout → host released. In harbor it
launches/kills board processes and then launches the L1 QEMU.

Built in `src/helm/power_sequencer.*` over a `Backplane` interface (slot
power and PERST#, slot link-ready, host power and PERST#). Decisions made
in the implementation:

- Boot holds the host, powers every slot, and waits for all of them
  together up to one `link_timeout`. A slot without link by then is
  powered off again, so a half-trained link is never on the host's bus,
  and faulted. The host is released either way: the device tree it
  enumerates is fixed, just without that slot.
- `power_cycle` touches only its slot. `check` faults a ready slot whose
  link dropped and retries up to `max_recoveries` power cycles. The
  sequencer tells an observer (`on_slot_ready`, `on_slot_recovered`,
  `on_slot_faulted`); helm's wiring reads the role's inventory into the
  CommandRouter on ready and calls `slot_power_cycled` on recovery, so
  functions return to the pool only after cleaning (Requirement 6.3).
- Time is injected (clock and sleep) so the sequence is unit-tested
  without waiting.
- harbor's `ProcessBackplane`: slot power is a board process
  (`posix_spawn`), link-ready is that process alive with its ready path
  (its sideband socket) present, and host power is the L1 QEMU process.
  A stale ready path is removed before each launch; power-off sends
  SIGTERM, waits a grace period, then SIGKILLs, and always reaps.

### ControllerLink

See `controller-interface` (design "ControllerLink"). Verifies envelope
shape and target server and forwards the signed slot image; never verifies
signatures itself (hull does — helm is not trusted to). Built in
`src/helm/controller_link.*`.

### HelmDaemon (helm main)

The event loop of the overview, built in `src/helm/helm_daemon.*`, with
`ak-helm` (`src/helm/helm_main.cpp`, configuration in
`src/helm/helm_config.*`) running it in harbor. Decisions made in the
implementation:

- One loop thread owns the router, pool, key store, sequencer and every
  OarLink. ControllerLink callbacks (its own thread, with its lock held)
  and the MailboxDevice's host slots only queue onto it; the inventory the
  ControllerSession sends is a snapshot the loop republishes after every
  pass, so the link thread never touches the router.
- Start order: slots boot and attach, the host is released, then the
  ControllerLink starts, so the first registration lists every function.
- On link-ready the daemon opens the slot's sideband (a `SocketBinding` to
  the board process in harbor), reads its inventory and calls `add_slot`.
  A sideband that cannot be opened or read is reported as a `device_lost`
  host fault once and retried on every check. A recovered slot gets a new
  sideband and inventory before `slot_power_cycled`. A faulted slot's
  sideband is closed, so requests for it fail as disconnected.
- MapUpdate frames go unmodified to every attached net role, which
  verifies the signature itself (helm verifies none); `on_map_applied` is
  called once every net role accepted it.
- The daemon never powers anything off on its own: stopping the loop leaves
  slots and host running (Requirement 2.3); `shutdown()` is explicit and
  `ak-helm` calls it on SIGTERM.
- Until the MailboxDevice (task 8) exists `ak-helm` uses a host port that
  refuses every post, so relayed commands are answered `internal_error`.
- Open: helm restarts with the router's `last_seq` at 0, so the controller,
  which resumes from the inventory's `last_command_seq`, would reuse
  sequence numbers hull already accepted. The floor needs to come from hull
  (its report) or from helm's audit log before commands can survive a helm
  restart.

## Data models

- `FunctionId { slot: u8, fn: u16 }`, globally `{server, slot, fn}`.
- `NicId` (u64, controller-assigned, never reused).
- `VmId`, `VolumeId`: u64, controller-assigned.
- Mapping table: `NicId → {vni, mac, owner_vtep}`, versioned per VPC.

## Error handling

All helm operations return `std::expected<T, HelmError>`. A failure after
partial progress triggers compensation (release reserved functions, drop
delivered keys) before reporting. Timeouts are first-class errors.

## Testing strategy

- Unit: mailbox codec (done), pool state machine (all transitions), key
  store with the software secure element, MCTP codec.
- Fuzz: mailbox (done), MCTP, controller envelope.
- harbor integration: create/destroy loops, detach under load, slot kill
  during cleaning, both placements.
