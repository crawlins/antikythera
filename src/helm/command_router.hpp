// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// CommandRouter: turns controller envelopes into device-pool reservations,
// key operations, data-plane requests and one mailbox command to hull, and
// hull's responses and events back into pool commits, cleaning and reports
// (.kiro/specs/helm-control-plane/ Requirements 1.5, 2.3, 3, 4, 9; design
// "CommandRouter").
//
// Per command:
//
//   1. Sequence. A slot sequence number not above the highest helm has
//      accepted is not relayed (Requirement 2.3). A retry of a command that
//      already finished gets its recorded outcome reported again, without
//      side effects; a retry of one still queued or in flight is ignored
//      (its outcome comes when it finishes); anything else is
//      stale_sequence.
//   2. Queue. The mailbox holds one command at a time (Requirement 1.5):
//      the next is dispatched when hull answers or the command times out.
//   3. Prepare. The slot is decoded (strictly; helm never checks the
//      signature, hull does) and the body's preconditions are checked
//      against helm's own state. Creative steps happen now, each with a
//      compensation: reserve a function (DevicePool::assign), prepare it on
//      its data-plane role, create a VM or volume key, store a new volume
//      on the storage role. A refused precondition or failed step undoes
//      the steps before it and reports the command without relaying it.
//   4. Relay. Audit, then the slot goes to the mailbox unmodified.
//   5. Commit or compensate. On ok or accepted, the command's destructive
//      steps happen now, only after hull verified the controller's
//      signature: release functions, destroy or rewrap keys, erase or
//      rewrite volumes on the media. ATTACH_VOLUME delivers the volume key
//      now too (below). On any other status the prepare steps are undone.
//
// Volumes (oar-blk Requirement 3). The storage role keeps each volume with
// its wrapped key in the volume's metadata on the media:
//
//   CREATE_VOLUME  prepare: create the volume key, then create_volume on
//                  the storage slot (the lowest connected blk slot) with
//                  the wrapped key; compensate: delete_volume, destroy key.
//   ATTACH_VOLUME  prepare: reserve the blk function (on the volume's
//                  slot) and prepare_function, which opens the volume;
//                  commit: unwrap and deliver the key. hull answers ok
//                  once the VMM has opened the function, and opening a
//                  VFIO device resets it (FLR), which wipes any key the
//                  function held; a driver reset afterwards keeps the key.
//                  So the key goes after the answer, and the function
//                  holds the guest's I/O until it arrives. A delivery that
//                  fails leaves the VM with a disk it cannot read: it is
//                  audited and reported as a device_lost host fault naming
//                  the slot and the volume, so the controller can detach.
//   DETACH_VOLUME  commit: release the function; cleaning drops the key
//                  and closes the volume.
//   DELETE_VOLUME  commit: destroy the wrapped key (crypto-erase), then
//                  delete_volume releases the space. DESTROY_VM without
//                  persist_volumes does the same for each of its volumes.
//   REWRAP_VOLUME  commit: rewrap in the KeyStore, then rewrap_volume
//                  writes the new owner and wrapped key to the media.
//
// Image volumes (oar-blk Requirement 8, task 13): CREATE_VOLUME with an
// image source creates no volume key. The storage role gets the store ID
// and image name instead, and the router keeps the owner itself. At
// ATTACH_VOLUME's commit the key delivered is a fresh ephemeral one from
// the secure element (KeyStore::create_ephemeral_key), never wrapped or
// kept, so the overlay written under it is unreadable once the function
// drops it. DELETE_VOLUME has no key to destroy, and DESTROY_VM without
// persist_volumes deletes the VM's image volumes too. REWRAP_VOLUME is
// unsupported until encrypted images give them a key to rewrap (task 15).
//
// A media step that fails after commit (delete or rewrap) cannot be undone
// either: it is counted in storage_failures. A failed delete leaves only
// ciphertext whose key is gone; a failed rewrap leaves the old wrapped key
// on the media, which matters once helm reloads keys from the media.
//
// Timeouts (Requirement 9.1). A command hull does not answer within
// command_timeout is reported timed_out and nothing else happens: helm
// cannot know whether hull applied it, so reservations stay held (a
// function hull may have attached is never handed to another VM) and the
// destructive steps, which wait for hull's ok, never run. Nothing is
// retried. The controller reconciles from the outcome and the inventory.
// A response that arrives later is audited and dropped. Data-plane
// requests time out inside OarLink and fail the command the same way.
//
// Releases and cleaning (Requirement 3.3, 3.4). A released function waits
// in `releasing` for hull's DEVICE_RELEASED (up to release_timeout), then
// its role cleans it: NIC and storage roles synchronously over the
// sideband; GPU functions wait for hull's SCRUB_DONE (up to
// clean_timeout). Failure or timeout faults the function until its slot is
// power-cycled (slot_power_cycled), after which it is cleaned again.
//
// Status (Requirement 9.2). Every command's outcome, every pool
// transition, VM exits and host faults go to the ReportSink as they
// happen; inventory() is the snapshot the ControllerSession sends on
// every connection.
//
// Audit (Requirement 9.3). Every accepted, refused, relayed and answered
// command and every key operation goes to the AuditLog. If a command's
// relay record cannot be written the command is not relayed (fails
// closed, internal_error); other audit failures are counted.
//
// NIC configuration. ATTACH_DEVICE for a NIC VF carries the VPC, NIC ID
// and MAC inside the signed command (mailbox v3), and the router hands
// exactly those to oar-net to prepare the VF (Requirement 8.1): helm adds
// no network identity of its own.
//
// Not thread-safe: the router, the pool, the key store and the ports
// belong to helm's event-loop thread.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include "helm/audit_log.hpp"
#include "helm/device_pool.hpp"
#include "helm/key_store.hpp"
#include "helm/mailbox.hpp"
#include "helm/oar_link.hpp"
#include "helm/oar_protocol.hpp"
#include "proto/envelope.hpp"
#include "proto/report.hpp"

namespace ak::helm {

// helm's side of the mailbox as the router uses it (MailboxDevice
// implements it). post_command writes the slot completely, then rings
// CMD_DOORBELL and raises the MSI (Requirement 1.3).
class HostPort {
public:
    HostPort() = default;
    HostPort(const HostPort&) = delete;
    auto operator=(const HostPort&) -> HostPort& = delete;
    HostPort(HostPort&&) = delete;
    auto operator=(HostPort&&) -> HostPort& = delete;
    virtual ~HostPort() = default;

    // False if the slot could not be written.
    virtual auto post_command(const mailbox::Slot& slot) -> bool = 0;
};

// One data-plane role's sideband, as the router uses it. OarLinkPort
// adapts an OarLink; tests substitute a fake.
class OarPort {
public:
    OarPort() = default;
    OarPort(const OarPort&) = delete;
    auto operator=(const OarPort&) -> OarPort& = delete;
    OarPort(OarPort&&) = delete;
    auto operator=(OarPort&&) -> OarPort& = delete;
    virtual ~OarPort() = default;

    virtual auto prepare_function(const oar::PrepareFunction& request)
        -> std::expected<void, LinkError> = 0;
    virtual auto clean_function(const oar::CleanFunction& request)
        -> std::expected<void, LinkError> = 0;
    virtual auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key)
        -> std::expected<void, LinkError> = 0;
    virtual auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> = 0;
    virtual auto create_volume(const oar::CreateVolume& request)
        -> std::expected<void, LinkError> = 0;
    virtual auto delete_volume(const oar::DeleteVolume& request)
        -> std::expected<void, LinkError> = 0;
    virtual auto rewrap_volume(const oar::RewrapVolume& request)
        -> std::expected<void, LinkError> = 0;
    // The network role's group policy and meters (GroupUsageReporter).
    virtual auto group_policy(std::span<const std::byte> /*frame*/)
        -> std::expected<void, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
    virtual auto group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
};

class OarLinkPort final : public OarPort {
public:
    explicit OarLinkPort(OarLink& link) noexcept : _link{&link} {}

    auto prepare_function(const oar::PrepareFunction& request)
        -> std::expected<void, LinkError> override;
    auto clean_function(const oar::CleanFunction& request)
        -> std::expected<void, LinkError> override;
    auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key)
        -> std::expected<void, LinkError> override;
    auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> override;
    auto create_volume(const oar::CreateVolume& request) -> std::expected<void, LinkError> override;
    auto delete_volume(const oar::DeleteVolume& request) -> std::expected<void, LinkError> override;
    auto rewrap_volume(const oar::RewrapVolume& request) -> std::expected<void, LinkError> override;
    auto group_policy(std::span<const std::byte> frame) -> std::expected<void, LinkError> override;
    auto group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> override;

private:
    OarLink* _link;
};

// Where status reports go (ControllerLink::report in helm).
class ReportSink {
public:
    ReportSink() = default;
    ReportSink(const ReportSink&) = delete;
    auto operator=(const ReportSink&) -> ReportSink& = delete;
    ReportSink(ReportSink&&) = delete;
    auto operator=(ReportSink&&) -> ReportSink& = delete;
    virtual ~ReportSink() = default;

    virtual auto report(proto::ReportBody body) -> void = 0;
};

struct RouterConfig {
    using Clock = std::chrono::steady_clock;

    // Highest sequence number already delivered (hull's floor, if known).
    std::uint64_t last_seq{0};
    std::chrono::milliseconds command_timeout{std::chrono::seconds{30}};
    // How long a released function may wait for DEVICE_RELEASED.
    std::chrono::milliseconds release_timeout{std::chrono::seconds{60}};
    // How long a GPU function may wait in `cleaning` for SCRUB_DONE.
    std::chrono::milliseconds clean_timeout{std::chrono::minutes{10}};
    // Envelopes waiting for the mailbox; more are refused.
    std::size_t max_queued{64};
    // Finished outcomes kept for answering retries.
    std::size_t outcome_history{256};
    // Empty: steady_clock::now.
    std::function<Clock::time_point()> clock;
};

struct RouterStats {
    std::uint64_t relayed{0};
    std::uint64_t refused{0};  // answered by helm without reaching hull
    std::uint64_t timed_out{0};
    std::uint64_t duplicates{0};      // retries answered from history or ignored
    std::uint64_t stray_messages{0};  // undecodable, unexpected or late hull messages
    std::uint64_t audit_failures{0};
    std::uint64_t inconsistencies{0};        // hull confirmed something helm's state disagrees with
    std::uint64_t key_delivery_failures{0};  // ATTACH_VOLUME succeeded, the key did not arrive
    std::uint64_t storage_failures{0};       // a committed delete or rewrap failed on the media
};

class CommandRouter {
public:
    using Clock = RouterConfig::Clock;

    // Every reference must outlive the router.
    CommandRouter(RouterConfig config, DevicePool& pool, KeyStore& keys, HostPort& host,
                  ReportSink& reports, AuditLog& audit);

    // Registers a data-plane role's sideband for `slot` (remembering its
    // role, so volumes go to a storage slot) and adds every
    // function its inventory lists; each starts in `cleaning` and is
    // cleaned now (PowerSequencer calls this once the slot is link-ready).
    auto add_slot(std::uint8_t slot, OarPort& port, const oar::Inventory& inventory) -> void;
    // The slot was power-cycled: faulted functions on it are cleaned again
    // and, if that succeeds, returned to the pool (Requirement 3.4, 6.3).
    auto slot_power_cycled(std::uint8_t slot) -> void;

    // A controller envelope (shape and server already checked by the
    // ControllerSession).
    auto on_envelope(const proto::Envelope& envelope) -> void;
    // A slot hull wrote: RSP_SLOT (a response) or EVT_SLOT (an event).
    auto on_host_slot(const mailbox::Slot& slot) -> void;
    // oar-net applied a mapping version (reported and kept for inventory).
    auto on_map_applied(std::uint32_t vni, std::uint64_t map_version) -> void;
    // Expires command, release and cleaning deadlines. Call it at least as
    // often as the shortest timeout's resolution you need.
    auto poll() -> void;

    // The inventory snapshot (Requirement 9.2); boot_id is left for the
    // ControllerSession to fill in, core and page counts for hull's report.
    [[nodiscard]] auto inventory() const -> proto::Inventory;
    [[nodiscard]] auto stats() const noexcept -> const RouterStats& { return _stats; }
    [[nodiscard]] auto busy() const noexcept -> bool { return _in_flight.has_value(); }
    [[nodiscard]] auto queued() const noexcept -> std::size_t { return _queue.size(); }

private:
    // What a command did before relay, so it can be undone.
    struct StoredVolume {
        VolumeId volume{0};
        std::uint8_t slot{0};
    };

    struct Undo {
        std::optional<FunctionId> reserved;  // assigned in the pool, maybe prepared
        std::optional<VmId> created_vm_key;
        std::optional<VolumeId> created_volume_key;
        std::optional<StoredVolume> stored_volume;  // created on the storage role
    };

    struct InFlight {
        std::uint64_t seq{0};
        mailbox::Body body;
        Undo undo;
        Clock::time_point deadline;
    };

    struct Vm {
        std::uint16_t vcpus{0};
        std::uint32_t memory_mib{0};
    };

    struct Volume {
        VmId owner{0};
        std::uint32_t size_gib{0};
        std::uint8_t slot{0};  // the storage slot holding it
        bool image{false};     // an image volume: no KeyStore entry, owner kept here
    };

    using Outcome = proto::CommandOutcome;

    [[nodiscard]] auto now() const -> Clock::time_point;
    auto pump() -> void;
    auto dispatch(const proto::Envelope& envelope) -> void;
    auto prepare(std::uint64_t seq, const mailbox::Body& body, Undo& undo)
        -> std::expected<void, mailbox::Status>;
    auto reserve(VmId vm, const mailbox::DeviceRef& device, Undo& undo)
        -> std::expected<FunctionId, mailbox::Status>;
    auto compensate(std::uint64_t seq, Undo& undo) -> void;
    auto commit(std::uint64_t seq, const mailbox::Body& body, const Undo& undo) -> void;
    auto deliver_volume_key(std::uint64_t seq, const mailbox::AttachVolume& attach) -> void;
    // Releases a volume's space on its storage role (after crypto-erase).
    auto erase_volume(VolumeId volume) -> void;
    // A volume's owner: the KeyStore's for a disk volume, ours for an image volume.
    [[nodiscard]] auto volume_owner(VolumeId volume) const -> std::optional<VmId>;
    [[nodiscard]] auto is_image_volume(VolumeId volume) const -> bool;
    [[nodiscard]] auto storage_slot() const -> std::optional<std::uint8_t>;
    auto finish(std::uint64_t seq, mailbox::Type command, mailbox::Status status,
                std::span<const std::byte> payload = {}) -> void;
    auto refuse(std::uint64_t seq, mailbox::Type command, mailbox::Status status) -> void;

    auto on_response(const mailbox::Message& msg) -> void;
    auto on_event(const mailbox::Body& body) -> void;

    // Pool moves that report themselves.
    auto pool_event(FunctionId id, PoolEvent event) -> bool;
    auto assign(FunctionId id, VmId vm) -> bool;
    auto release(FunctionId id, VmId vm) -> bool;
    auto start_cleaning(FunctionId id) -> void;
    auto report_transition(FunctionId id, FunctionState from, const FunctionInfo& after,
                           std::optional<VmId> vm) -> void;

    auto audit(const AuditRecord& record) -> bool;
    auto port_for(std::uint8_t slot) -> OarPort*;

    RouterConfig _config;
    DevicePool* _pool;
    KeyStore* _keys;
    HostPort* _host;
    ReportSink* _reports;
    AuditLog* _audit;

    std::map<std::uint8_t, OarPort*> _ports;
    std::map<std::uint8_t, oar::Role> _roles;
    std::uint64_t _last_seq;
    std::deque<proto::Envelope> _queue;
    std::optional<InFlight> _in_flight;
    std::set<std::uint64_t> _timed_out;         // relayed, timed out, answer not yet seen
    std::map<std::uint64_t, Outcome> _history;  // finished outcomes, for retries

    std::map<FunctionId, Clock::time_point> _deadlines;  // releasing / GPU cleaning
    std::map<VmId, Vm> _vms;
    std::map<VolumeId, Volume> _volumes;
    std::map<VolumeId, FunctionId> _attached;          // volume -> blk function serving it
    std::map<std::uint32_t, std::uint64_t> _networks;  // vni -> applied map version

    RouterStats _stats;
};

}  // namespace ak::helm
