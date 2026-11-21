// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The controller's volume state machine, specified by code
// (.kiro/specs/block-volume-service/ design "Controller reference model",
// task 4). The kythira EC2 module ports it (or links it); the simulation
// and harbor's test controller drive it. It owns every network volume's
// replica set (Requirement 6.1) and decides, and only it decides:
//
//   placement     replicas on distinct servers, and distinct racks and
//                 power domains where the inventory names them; a
//                 placement that cannot honour that is refused (5.1-5.2).
//   epochs        every change of members, roles, attachments, size, QoS
//                 or flags commits epoch + 1 and publishes one
//                 ReplicaConfig per recipient server, members first, then
//                 the attachments' servers (6.2).
//   generations   each attach takes a new generation; detach retires it,
//                 and generation_fenced() says when the primary has
//                 applied the epoch without it (6.4, 6.9).
//   leases        a replica_status from the primary at the current epoch
//                 is its lease request and is acknowledged through the
//                 transport; no other replica is promoted until
//                 lease_ms x (1 + margin) after the last acknowledgement,
//                 or the old primary confirmed its demotion (6.3).
//   failures      a secondary the primary reports, or one whose server
//                 falls silent, leaves the in-sync set at a new epoch
//                 (6.5); a primary reported by its initiator and
//                 confirmed (by a member's report, its own fault, or its
//                 server's silence) stops getting lease acknowledgements
//                 and is replaced by the in-sync secondary with the
//                 highest reported sequence once its lease has run out
//                 (6.6); with no in-sync replica left the volume is
//                 io_suspended and impaired until enable_io() (6.8).
//   rebuild       a volume short of its replication factor gets a joining
//                 replica: the same server when a replica it lost comes
//                 back (or still reachable, after rejoin_after) within the
//                 resync window (partial resync), another server otherwise; fewest in-sync replicas
//                 first, then class priority, with global and per-server limits so a server loss is
//                 rebuilt many-to-many (7.1-7.5).
//   moves         target joins, becomes a secondary, then the source
//                 leaves; a primary hands over (leaving, drain,
//                 demotion_confirmed or lease expiry, then the target is
//                 primary) and the replica count never drops (8.1-8.5);
//                 drain() moves everything off a server (8.4).
//   snapshots     a cut over one or more volumes (prepare to every
//                 primary, commit to every member once all have
//                 prepared, abort on a refusal or timeout), then an
//                 upload by a secondary; deleting snapshots schedules
//                 one mark-and-sweep per lineage at a time, during which
//                 that lineage's uploads wait (11.1-11.3, 11.8).
//   erasure       when a lineage has no volume and no snapshot left its
//                 key is destroyed, once, and the lineage is never reused
//                 (12.4).
//
// Single-threaded and deterministic: time is passed in (any monotonic
// origin), and the only outputs are Transport calls. VolumeOps are resent
// on tick() until their outcome arrives (roles run an op_id at most once),
// and a member that has not applied the current epoch is sent its config
// again. Frames leave unsigned with no key_id: the transport signs them.
//
// Not modelled here: clones, scrub scheduling, hydration progress and
// class changes that alter the replica count (later tasks).

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include "proto/replica_config.hpp"
#include "proto/report.hpp"
#include "proto/volume_op.hpp"

namespace ak::hold::master {

using Time = std::chrono::milliseconds;  // controller monotonic clock

// What the master sends. One ReplicaConfig per recipient (server_id
// inside); VolumeOps likewise.
class Transport {
public:
    Transport() = default;
    Transport(const Transport&) = delete;
    auto operator=(const Transport&) -> Transport& = delete;
    Transport(Transport&&) = delete;
    auto operator=(Transport&&) -> Transport& = delete;
    virtual ~Transport() = default;

    virtual auto send_config(const proto::ReplicaConfig& config) -> void = 0;
    virtual auto send_op(const proto::VolumeOp& op) -> void = 0;
    // Acknowledges the lease request of `server`, primary of `volume` at
    // `epoch`; the primary's lease runs lease_ms from when it asked.
    virtual auto grant_lease(std::uint64_t server, std::uint64_t volume, std::uint64_t epoch)
        -> void = 0;
    // Mark and sweep: delete every chunk object of `lineage` not named by
    // one of `live` manifests; call Master::gc_finished when done.
    virtual auto sweep_lineage(std::uint64_t lineage, std::span<const proto::ManifestName> live)
        -> void = 0;
    // The lineage's last volume and snapshot are gone: destroy its KMS key.
    virtual auto destroy_lineage_key(std::uint64_t lineage) -> void = 0;
};

struct Timing {
    Time server_silence{10'000};  // a hold role silent this long is down
    std::uint32_t lease_ms{4000};
    std::uint32_t lease_margin_pct{10};  // clock-rate error allowance
    std::uint32_t resync_window_s{900};
    Time suspicion_ttl{10'000};  // an unconfirmed primary_timeout expires
    // A replica out of the set whose server still reports rejoins (partial
    // resync) after this, so a flapping link does not churn epochs.
    Time rejoin_after{30'000};
    Time retry{1000};  // VolumeOp and config resend interval
    std::uint32_t prepare_timeout_ms{1000};
};

struct Limits {
    std::size_t rebuilds{16};            // joining replicas at once, all volumes
    std::size_t rebuilds_per_server{2};  // joining replicas per target server
    std::size_t drain_moves{4};          // moves started by drain() at once
};

// Controller policy carried as numbers (design "QoS and elasticity").
struct VolumeClass {
    std::uint8_t replicas{2};  // 2 to 5
    proto::VolumeQos qos{};
    bool multi_attach_allowed{false};
    std::uint8_t priority{0};  // rebuild order among equals: higher first
};

[[nodiscard]] auto general_class() noexcept -> VolumeClass;      // gp3-like
[[nodiscard]] auto provisioned_class() noexcept -> VolumeClass;  // io2-like

struct StorageServer {
    std::uint64_t server_id{0};
    proto::StorageEndpoint endpoint{};
    std::uint16_t port{0};
    std::uint32_t rack{0};   // 0: not reported
    std::uint32_t power{0};  // 0: not reported
    std::uint64_t capacity_bytes{0};
};

struct VolumeSpec {
    std::uint64_t volume_id{0};
    std::uint64_t lineage_id{0};
    std::uint64_t capacity_blocks{0};
    std::uint32_t block_size{proto::block_size_4096};
    VolumeClass volume_class{general_class()};
    bool multi_attach{false};
    proto::VolumeSource source{};
};

enum class Error : std::uint8_t {
    bad_spec,
    duplicate_server,
    unknown_server,
    duplicate_volume,
    unknown_volume,
    erased_lineage,    // its key was destroyed; IDs are never reused
    no_placement,      // not enough servers in distinct failure domains
    attachment_limit,  // 16 already
    duplicate_attachment,
    unknown_attachment,
    multi_attach_needed,  // a second read-write attachment without multi_attach
    attached,             // delete with attachments left
    suspended,            // no primary to serve or copy from
    busy,                 // a move or snapshot is already running on it
    not_member,
    shrink,  // volumes only grow
    not_suspended,
    no_candidate,  // enable_io: no surviving replica reachable
    unknown_snapshot,
    duplicate_snapshot,
};

[[nodiscard]] auto to_string(Error e) noexcept -> const char*;

struct Member {
    std::uint64_t server_id{0};
    proto::ReplicaRole role{proto::ReplicaRole::secondary};
    std::uint32_t replica_gen{0};
    std::uint64_t applied_epoch{0};  // from replica_status
    std::uint64_t last_seq{0};
    bool replacement{false};  // a rebuild target a returning replica may displace
};

// A replica out of the in-sync set, kept for partial resync.
struct AwayReplica {
    std::uint64_t server_id{0};
    std::uint32_t replica_gen{0};
    std::uint64_t last_seq{0};
    Time since{0};
};

struct Move {
    std::uint64_t from{0};
    std::uint64_t to{0};
    bool handing_over{false};  // the source is primary and now leaving
    bool demotion_confirmed{false};
};

struct Volume {
    VolumeSpec spec;
    std::uint64_t epoch{0};
    std::uint32_t flags{0};
    proto::VolumeQos qos{};
    std::vector<Member> members;  // ascending server_id
    std::vector<AwayReplica> away;
    std::vector<proto::VolumeAttachment> attachments;  // ascending attachment_id
    std::map<std::uint32_t, std::uint64_t> retired;    // generation -> epoch without it
    std::uint32_t next_generation{1};
    std::uint32_t next_replica_gen{1};
    std::optional<Time> lease_acked;
    std::set<std::uint64_t> primary_suspects;  // reporters of primary_timeout
    std::optional<Time> suspected_at;
    bool failover{false};  // confirmed: no more lease, replace when it runs out
    std::optional<Move> move;
    bool loss_possible{false};  // enable_io resumed from a replica not known in sync
    std::optional<proto::ManifestName> last_manifest;
    Time published{0};
};

enum class SnapshotStatus : std::uint8_t {
    preparing,
    uploading,
    completed,
    failed,
};

struct SnapshotPart {
    std::uint64_t volume_id{0};
    std::uint64_t lineage_id{0};
    bool prepared{false};
    std::uint64_t cut_seq{0};
    std::uint64_t uploader{0};
    bool upload_sent{false};
    std::optional<proto::ManifestName> manifest;
};

struct Snapshot {
    std::uint64_t snapshot_id{0};  // also the cut_id
    std::uint32_t store_id{0};
    SnapshotStatus status{SnapshotStatus::preparing};
    Time started{0};
    std::vector<SnapshotPart> parts;
};

class Master {
public:
    Master(Transport& transport, Timing timing = {}, Limits limits = {}) noexcept
        : _transport{&transport}, _timing{timing}, _limits{limits} {}

    // ---- inventory -----------------------------------------------------
    [[nodiscard]] auto add_server(const StorageServer& server, Time now)
        -> std::expected<void, Error>;
    // Starts moving every replica off `server`; drained() when done.
    [[nodiscard]] auto drain(std::uint64_t server) -> std::expected<void, Error>;
    [[nodiscard]] auto drained(std::uint64_t server) const -> bool;
    [[nodiscard]] auto server_up(std::uint64_t server) const -> bool;

    // ---- volumes -------------------------------------------------------
    [[nodiscard]] auto create_volume(const VolumeSpec& spec, Time now)
        -> std::expected<void, Error>;
    [[nodiscard]] auto delete_volume(std::uint64_t volume, Time now) -> std::expected<void, Error>;
    // A new attachment; returns its generation.
    [[nodiscard]] auto attach(std::uint64_t volume, std::uint64_t attachment_id,
                              std::uint64_t server, proto::AttachMode mode, Time now)
        -> std::expected<std::uint32_t, Error>;
    // Retires the attachment's generation (detach, forced detach, replace).
    [[nodiscard]] auto detach(std::uint64_t volume, std::uint64_t attachment_id, Time now)
        -> std::expected<void, Error>;
    // True once the primary has applied an epoch without `generation`:
    // a forced detach may unplug, another server may attach (6.9).
    [[nodiscard]] auto generation_fenced(std::uint64_t volume, std::uint32_t generation) const
        -> bool;
    [[nodiscard]] auto resize(std::uint64_t volume, std::uint64_t capacity_blocks, Time now)
        -> std::expected<void, Error>;
    [[nodiscard]] auto set_qos(std::uint64_t volume, const proto::VolumeQos& qos, Time now)
        -> std::expected<void, Error>;
    // Resumes an io_suspended volume from its best surviving replica,
    // accepting the loss of recent writes (Requirement 6.8).
    [[nodiscard]] auto enable_io(std::uint64_t volume, Time now) -> std::expected<void, Error>;
    // Moves the replica on `from` to `to` (0: the master picks).
    [[nodiscard]] auto move_replica(std::uint64_t volume, std::uint64_t from, std::uint64_t to,
                                    Time now) -> std::expected<void, Error>;

    // ---- snapshots -----------------------------------------------------
    // A crash-consistent cut of `volumes` (one or more), uploaded to
    // `store_id`.
    [[nodiscard]] auto create_snapshot(std::uint64_t snapshot_id,
                                       std::span<const std::uint64_t> volumes,
                                       std::uint32_t store_id, Time now)
        -> std::expected<void, Error>;
    [[nodiscard]] auto delete_snapshot(std::uint64_t snapshot_id, Time now)
        -> std::expected<void, Error>;
    // The transport's sweep of `lineage` finished.
    auto gc_finished(std::uint64_t lineage, Time now) -> void;

    // ---- inputs --------------------------------------------------------
    auto on_report(const proto::Report& report, Time now) -> void;
    auto tick(Time now) -> void;

    // ---- queries -------------------------------------------------------
    [[nodiscard]] auto volume(std::uint64_t id) const -> const Volume*;
    [[nodiscard]] auto snapshot(std::uint64_t id) const -> const Snapshot*;
    // The config `server` gets for `volume` at its current epoch.
    [[nodiscard]] auto config_for(const Volume& v, std::uint64_t server) const
        -> proto::ReplicaConfig;
    [[nodiscard]] auto pending_ops() const -> std::size_t { return _ops.size(); }
    [[nodiscard]] auto lineage_erased(std::uint64_t lineage) const -> bool {
        return _erased.contains(lineage);
    }

private:
    struct Server {
        StorageServer info;
        Time last_seen{0};
        bool up{true};
        bool draining{false};
    };
    struct PendingOp {
        proto::VolumeOp op;
        Time sent{0};
    };
    struct Lineage {
        bool gc_wanted{false};
        bool gc_running{false};
    };

    [[nodiscard]] auto find(std::uint64_t volume) -> Volume*;
    [[nodiscard]] auto live(std::uint64_t volume) -> std::expected<Volume*, Error>;
    [[nodiscard]] auto used_bytes(std::uint64_t server) const -> std::uint64_t;
    [[nodiscard]] auto joining_on(std::uint64_t server) const -> std::size_t;
    [[nodiscard]] auto joining_total() const -> std::size_t;
    // `count` servers with room for `bytes`, distinct from each other and
    // from `keep` in every reported failure domain, never one of
    // `exclude`; only `only` when it is not 0.
    [[nodiscard]] auto place(std::uint64_t bytes, std::size_t count,
                             const std::vector<std::uint64_t>& keep,
                             const std::vector<std::uint64_t>& exclude,
                             std::uint64_t only = 0) const
        -> std::optional<std::vector<std::uint64_t>>;

    auto commit(Volume& v, Time now, const std::vector<std::uint64_t>& also = {}) -> void;
    auto publish(const Volume& v, std::uint64_t server) -> void;
    auto send_op(const Volume& v, std::uint64_t server, proto::VolumeOpArgs args, Time now) -> void;
    auto delete_replica(const Volume& v, std::uint64_t server, std::uint32_t replica_gen, Time now)
        -> void;

    [[nodiscard]] auto lease_expired(const Volume& v, Time now) const -> bool;
    // Takes the member on `server` out of the in-sync set (to `away`).
    auto drop_member(Volume& v, std::uint64_t server, Time now) -> void;
    auto confirm_failover(Volume& v, Time now) -> void;
    auto fail_over(Volume& v, Time now) -> void;
    auto promote_joined(Volume& v, Member& m, Time now) -> void;
    auto finish_handover(Volume& v, Time now) -> void;
    auto start_move(Volume& v, std::uint64_t from, std::uint64_t to, Time now)
        -> std::expected<void, Error>;
    auto server_returned(std::uint64_t server, Time now) -> void;
    auto server_lost(std::uint64_t server, Time now) -> void;
    auto schedule_rebuilds(Time now) -> void;
    auto schedule_drains(Time now) -> void;
    // Fails uploads of `volume` whose uploader on `server` left the set.
    auto uploader_lost(std::uint64_t volume, std::uint64_t server) -> void;

    auto on_status(std::uint64_t server, const proto::ReplicaStatusEntry& e, Time now) -> void;
    auto on_fault(std::uint64_t server, const proto::VolumeFault& f, Time now) -> void;
    auto on_demotion(std::uint64_t server, const proto::DemotionConfirmed& d, Time now) -> void;
    auto on_outcome(std::uint64_t server, const proto::OpOutcome& o, Time now) -> void;
    auto on_progress(std::uint64_t server, const proto::SnapshotProgress& p, Time now) -> void;

    auto abort_snapshot(Snapshot& s, Time now) -> void;
    auto commit_snapshot(Snapshot& s, Time now) -> void;
    auto send_uploads(Time now) -> void;
    auto maybe_erase(std::uint64_t lineage) -> void;
    auto run_gc() -> void;
    // The newest completed manifest of `volume` among remaining snapshots.
    [[nodiscard]] auto newest_manifest(std::uint64_t volume) const
        -> std::optional<proto::ManifestName>;

    Transport* _transport;
    Timing _timing;
    Limits _limits;
    std::map<std::uint64_t, Server> _servers;
    std::map<std::uint64_t, Volume> _volumes;
    std::map<std::uint64_t, Snapshot> _snapshots;
    std::map<std::uint64_t, Lineage> _lineages;
    std::set<std::uint64_t> _erased;
    std::map<std::uint64_t, PendingOp> _ops;  // by op_id
    std::uint64_t _next_op{1};
};

}  // namespace ak::hold::master
