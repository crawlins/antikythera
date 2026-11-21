// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/master/master.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <tuple>
#include <utility>
#include <variant>

namespace ak::hold::master {

namespace {

using proto::ReplicaRole;

constexpr std::uint8_t min_replicas = 2;
constexpr std::uint32_t percent = 100;
constexpr std::uint32_t ms_per_s = 1000;

auto in_sync(const Member& m) noexcept -> bool {
    return m.role == ReplicaRole::primary || m.role == ReplicaRole::secondary;
}

auto member_on(Volume& v, std::uint64_t server) noexcept -> Member* {
    const auto it = std::ranges::find(v.members, server, &Member::server_id);
    return it == v.members.end() ? nullptr : &*it;
}

auto member_on(const Volume& v, std::uint64_t server) noexcept -> const Member* {
    const auto it = std::ranges::find(v.members, server, &Member::server_id);
    return it == v.members.end() ? nullptr : &*it;
}

auto primary_of(Volume& v) noexcept -> Member* {
    const auto it = std::ranges::find(v.members, ReplicaRole::primary, &Member::role);
    return it == v.members.end() ? nullptr : &*it;
}

auto primary_of(const Volume& v) noexcept -> const Member* {
    const auto it = std::ranges::find(v.members, ReplicaRole::primary, &Member::role);
    return it == v.members.end() ? nullptr : &*it;
}

auto in_sync_count(const Volume& v) noexcept -> std::size_t {
    return static_cast<std::size_t>(std::ranges::count_if(v.members, in_sync));
}

auto joining_count(const Volume& v) noexcept -> std::size_t {
    return static_cast<std::size_t>(
        std::ranges::count(v.members, ReplicaRole::joining, &Member::role));
}

auto add_member(Volume& v, Member m) -> void {
    v.members.push_back(m);
    std::ranges::sort(v.members, {}, &Member::server_id);
}

auto remove_member(Volume& v, std::uint64_t server) -> void {
    std::erase_if(v.members, [&](const Member& m) { return m.server_id == server; });
}

auto suspended(const Volume& v) noexcept -> bool {
    return (v.flags & proto::replica_flags::io_suspended) != 0;
}

auto valid_qos(const proto::VolumeQos& q) noexcept -> bool {
    return q.iops != 0 && q.mib_per_s != 0 && q.burst_iops >= q.iops && q.burst_mib >= q.mib_per_s;
}

auto bytes_of(const VolumeSpec& s) noexcept -> std::uint64_t {
    return s.capacity_blocks * s.block_size;
}

auto domains_clash(const StorageServer& a, const StorageServer& b) noexcept -> bool {
    return (a.rack != 0 && a.rack == b.rack) || (a.power != 0 && a.power == b.power);
}

auto contains(const std::vector<std::uint64_t>& v, std::uint64_t x) -> bool {
    return std::ranges::find(v, x) != v.end();
}

}  // namespace

auto general_class() noexcept -> VolumeClass {
    return {.replicas = 2,
            .qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 16'000, .burst_mib = 1000},
            .multi_attach_allowed = false,
            .priority = 0};
}

auto provisioned_class() noexcept -> VolumeClass {
    return {.replicas = 3,
            .qos = {.iops = 16'000, .mib_per_s = 1000, .burst_iops = 64'000, .burst_mib = 2000},
            .multi_attach_allowed = true,
            .priority = 1};
}

auto to_string(Error e) noexcept -> const char* {
    switch (e) {
        case Error::bad_spec:
            return "bad_spec";
        case Error::duplicate_server:
            return "duplicate_server";
        case Error::unknown_server:
            return "unknown_server";
        case Error::duplicate_volume:
            return "duplicate_volume";
        case Error::unknown_volume:
            return "unknown_volume";
        case Error::erased_lineage:
            return "erased_lineage";
        case Error::no_placement:
            return "no_placement";
        case Error::attachment_limit:
            return "attachment_limit";
        case Error::duplicate_attachment:
            return "duplicate_attachment";
        case Error::unknown_attachment:
            return "unknown_attachment";
        case Error::multi_attach_needed:
            return "multi_attach_needed";
        case Error::attached:
            return "attached";
        case Error::suspended:
            return "suspended";
        case Error::busy:
            return "busy";
        case Error::not_member:
            return "not_member";
        case Error::shrink:
            return "shrink";
        case Error::not_suspended:
            return "not_suspended";
        case Error::no_candidate:
            return "no_candidate";
        case Error::unknown_snapshot:
            return "unknown_snapshot";
        case Error::duplicate_snapshot:
            return "duplicate_snapshot";
    }
    return "unknown";
}

// ---- inventory -------------------------------------------------------------

auto Master::add_server(const StorageServer& server, Time now) -> std::expected<void, Error> {
    if (server.server_id == 0 || server.port == 0 || server.capacity_bytes == 0 ||
        !proto::detail::unicast(server.endpoint)) {
        return std::unexpected(Error::bad_spec);
    }
    if (_servers.contains(server.server_id)) {
        return std::unexpected(Error::duplicate_server);
    }
    _servers.emplace(server.server_id,
                     Server{.info = server, .last_seen = now, .up = true, .draining = false});
    return {};
}

auto Master::drain(std::uint64_t server) -> std::expected<void, Error> {
    const auto it = _servers.find(server);
    if (it == _servers.end()) {
        return std::unexpected(Error::unknown_server);
    }
    it->second.draining = true;
    return {};
}

auto Master::drained(std::uint64_t server) const -> bool {
    const auto it = _servers.find(server);
    if (it == _servers.end() || !it->second.draining) {
        return false;
    }
    for (const auto& [id, v] : _volumes) {
        if (member_on(v, server) != nullptr ||
            std::ranges::find(v.away, server, &AwayReplica::server_id) != v.away.end()) {
            return false;
        }
    }
    return std::ranges::none_of(_ops,
                                [&](const auto& kv) { return kv.second.op.server_id == server; });
}

auto Master::server_up(std::uint64_t server) const -> bool {
    const auto it = _servers.find(server);
    return it != _servers.end() && it->second.up;
}

auto Master::used_bytes(std::uint64_t server) const -> std::uint64_t {
    std::uint64_t used = 0;
    for (const auto& [id, v] : _volumes) {
        const bool here =
            member_on(v, server) != nullptr ||
            std::ranges::find(v.away, server, &AwayReplica::server_id) != v.away.end();
        if (here) {
            used += bytes_of(v.spec);
        }
    }
    return used;
}

auto Master::joining_on(std::uint64_t server) const -> std::size_t {
    std::size_t n = 0;
    for (const auto& [id, v] : _volumes) {
        const Member* m = member_on(v, server);
        n += (m != nullptr && m->role == ReplicaRole::joining) ? 1 : 0;
    }
    return n;
}

auto Master::joining_total() const -> std::size_t {
    std::size_t n = 0;
    for (const auto& [id, v] : _volumes) {
        n += joining_count(v);
    }
    return n;
}

auto Master::place(std::uint64_t bytes, std::size_t count, const std::vector<std::uint64_t>& keep,
                   const std::vector<std::uint64_t>& exclude, std::uint64_t only) const
    -> std::optional<std::vector<std::uint64_t>> {
    struct Candidate {
        std::uint64_t id;
        std::size_t joining;
        std::uint64_t used;
        const StorageServer* info;
    };
    std::vector<Candidate> candidates;
    for (const auto& [id, s] : _servers) {
        if (!s.up || s.draining || (only != 0 && id != only) || contains(keep, id) ||
            contains(exclude, id)) {
            continue;
        }
        const std::uint64_t used = used_bytes(id);
        const std::size_t joining = joining_on(id);
        if (used > s.info.capacity_bytes || s.info.capacity_bytes - used < bytes ||
            joining >= _limits.rebuilds_per_server) {
            continue;
        }
        candidates.push_back({.id = id, .joining = joining, .used = used, .info = &s.info});
    }
    // Least busy, then least full, then lowest ID: deterministic.
    std::ranges::sort(candidates, {},
                      [](const Candidate& c) { return std::tuple{c.joining, c.used, c.id}; });
    std::vector<const StorageServer*> taken;
    for (const auto id : keep) {
        if (const auto it = _servers.find(id); it != _servers.end()) {
            taken.push_back(&it->second.info);
        }
    }
    std::vector<std::uint64_t> chosen;
    // Depth-first so a greedy dead end never refuses a placement that
    // exists (replica sets are small).
    const std::function<bool(std::size_t)> search = [&](std::size_t from) -> bool {
        if (chosen.size() == count) {
            return true;
        }
        for (std::size_t i = from; i < candidates.size(); ++i) {
            const Candidate& c = candidates[i];
            if (std::ranges::any_of(
                    taken, [&](const StorageServer* t) { return domains_clash(*t, *c.info); })) {
                continue;
            }
            chosen.push_back(c.id);
            taken.push_back(c.info);
            if (search(i + 1)) {
                return true;
            }
            chosen.pop_back();
            taken.pop_back();
        }
        return false;
    };
    if (!search(0)) {
        return std::nullopt;
    }
    return chosen;
}

// ---- publishing ------------------------------------------------------------

auto Master::config_for(const Volume& v, std::uint64_t server) const -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.server_id = server;
    c.volume_id = v.spec.volume_id;
    c.epoch = v.epoch;
    c.lineage_id = v.spec.lineage_id;
    c.capacity_blocks = v.spec.capacity_blocks;
    c.block_size = v.spec.block_size;
    c.flags = v.flags;
    c.qos = v.qos;
    c.lease_ms = _timing.lease_ms;
    c.resync_window_s = _timing.resync_window_s;
    c.source = v.spec.source;
    for (const auto& m : v.members) {
        const auto it = _servers.find(m.server_id);
        c.members.push_back({.server_id = m.server_id,
                             .endpoint = it->second.info.endpoint,
                             .port = it->second.info.port,
                             .role = m.role,
                             .replica_gen = m.replica_gen});
    }
    c.attachments = v.attachments;
    return c;
}

auto Master::publish(const Volume& v, std::uint64_t server) -> void {
    _transport->send_config(config_for(v, server));
}

auto Master::commit(Volume& v, Time now, const std::vector<std::uint64_t>& also) -> void {
    ++v.epoch;
    v.primary_suspects.clear();
    v.suspected_at.reset();
    v.published = now;
    // Members first, so the replica set has the epoch before initiators
    // act on it; then the attachments' servers; then anyone just removed.
    std::vector<std::uint64_t> sent;
    auto send = [&](std::uint64_t server) {
        if (!contains(sent, server)) {
            sent.push_back(server);
            publish(v, server);
        }
    };
    for (const auto& m : v.members) {
        send(m.server_id);
    }
    for (const auto& a : v.attachments) {
        send(a.server_id);
    }
    for (const auto s : also) {
        send(s);
    }
}

auto Master::send_op(const Volume& v, std::uint64_t server, proto::VolumeOpArgs args, Time now)
    -> void {
    proto::VolumeOp op{.key_id = proto::no_key_id,
                       .server_id = server,
                       .volume_id = v.spec.volume_id,
                       .epoch = v.epoch,
                       .op_id = _next_op++,
                       .args = std::move(args),
                       .signature = {}};
    _ops.emplace(op.op_id, PendingOp{.op = op, .sent = now});
    _transport->send_op(op);
}

auto Master::delete_replica(const Volume& v, std::uint64_t server, std::uint32_t replica_gen,
                            Time now) -> void {
    send_op(v, server, proto::DeleteReplica{.replica_gen = replica_gen}, now);
}

// ---- volumes ---------------------------------------------------------------

auto Master::find(std::uint64_t volume) -> Volume* {
    const auto it = _volumes.find(volume);
    return it == _volumes.end() ? nullptr : &it->second;
}

auto Master::volume(std::uint64_t id) const -> const Volume* {
    const auto it = _volumes.find(id);
    return it == _volumes.end() ? nullptr : &it->second;
}

auto Master::snapshot(std::uint64_t id) const -> const Snapshot* {
    const auto it = _snapshots.find(id);
    return it == _snapshots.end() ? nullptr : &it->second;
}

auto Master::live(std::uint64_t volume) -> std::expected<Volume*, Error> {
    Volume* v = find(volume);
    if (v == nullptr) {
        return std::unexpected(Error::unknown_volume);
    }
    return v;
}

auto Master::create_volume(const VolumeSpec& spec, Time now) -> std::expected<void, Error> {
    const VolumeClass& cls = spec.volume_class;
    const bool source_ok = spec.source.kind == proto::SourceKind::none
                               ? spec.source == proto::VolumeSource{}
                               : (spec.source.kind == proto::SourceKind::snapshot ||
                                  spec.source.kind == proto::SourceKind::image);
    if (spec.volume_id == 0 || spec.lineage_id == 0 || spec.capacity_blocks == 0 ||
        (spec.block_size != proto::block_size_512 && spec.block_size != proto::block_size_4096) ||
        spec.capacity_blocks > std::numeric_limits<std::uint64_t>::max() / spec.block_size ||
        cls.replicas < min_replicas || cls.replicas > proto::max_replica_members ||
        !valid_qos(cls.qos) || (spec.multi_attach && !cls.multi_attach_allowed) || !source_ok) {
        return std::unexpected(Error::bad_spec);
    }
    if (_erased.contains(spec.lineage_id)) {
        return std::unexpected(Error::erased_lineage);
    }
    if (_volumes.contains(spec.volume_id)) {
        return std::unexpected(Error::duplicate_volume);
    }
    const auto servers = place(bytes_of(spec), cls.replicas, {}, {});
    if (!servers) {
        return std::unexpected(Error::no_placement);
    }
    Volume v;
    v.spec = spec;
    v.qos = cls.qos;
    v.flags = spec.multi_attach ? proto::replica_flags::multi_attach : 0U;
    for (std::size_t i = 0; i < servers->size(); ++i) {
        // The least loaded server leads; new replicas start empty and in sync.
        add_member(v, {.server_id = (*servers)[i],
                       .role = i == 0 ? ReplicaRole::primary : ReplicaRole::secondary,
                       .replica_gen = v.next_replica_gen++,
                       .applied_epoch = 0,
                       .last_seq = 0,
                       .replacement = false});
    }
    _lineages.try_emplace(spec.lineage_id);
    auto& stored = _volumes.emplace(spec.volume_id, std::move(v)).first->second;
    commit(stored, now);
    return {};
}

auto Master::delete_volume(std::uint64_t volume, Time now) -> std::expected<void, Error> {
    auto v = live(volume);
    if (!v) {
        return std::unexpected(v.error());
    }
    if (!(*v)->attachments.empty()) {
        return std::unexpected(Error::attached);
    }
    for (const auto& [id, s] : _snapshots) {
        if (s.status == SnapshotStatus::preparing &&
            std::ranges::find(s.parts, volume, &SnapshotPart::volume_id) != s.parts.end()) {
            return std::unexpected(Error::busy);
        }
    }
    // Gone from the catalog at once: the delete ops are resent until each
    // replica confirms, and the lineage key goes with its last volume.
    const Volume doomed = std::move(**v);
    _volumes.erase(volume);
    for (const auto& m : doomed.members) {
        delete_replica(doomed, m.server_id, m.replica_gen, now);
    }
    for (const auto& a : doomed.away) {
        delete_replica(doomed, a.server_id, a.replica_gen, now);
    }
    maybe_erase(doomed.spec.lineage_id);
    return {};
}

auto Master::attach(std::uint64_t volume, std::uint64_t attachment_id, std::uint64_t server,
                    proto::AttachMode mode, Time now) -> std::expected<std::uint32_t, Error> {
    auto r = live(volume);
    if (!r) {
        return std::unexpected(r.error());
    }
    Volume& v = **r;
    if (attachment_id == 0 || server == 0 ||
        (mode != proto::AttachMode::rw && mode != proto::AttachMode::ro)) {
        return std::unexpected(Error::bad_spec);
    }
    if (std::ranges::find(v.attachments, attachment_id, &proto::VolumeAttachment::attachment_id) !=
        v.attachments.end()) {
        return std::unexpected(Error::duplicate_attachment);
    }
    if (v.attachments.size() >= proto::max_volume_attachments) {
        return std::unexpected(Error::attachment_limit);
    }
    const bool multi = (v.flags & proto::replica_flags::multi_attach) != 0;
    if (mode == proto::AttachMode::rw && !multi &&
        std::ranges::any_of(v.attachments, [](const proto::VolumeAttachment& a) {
            return a.mode == proto::AttachMode::rw;
        })) {
        return std::unexpected(Error::multi_attach_needed);
    }
    const std::uint32_t generation = v.next_generation++;
    v.attachments.push_back({.attachment_id = attachment_id,
                             .server_id = server,
                             .generation = generation,
                             .mode = mode});
    std::ranges::sort(v.attachments, {}, &proto::VolumeAttachment::attachment_id);
    commit(v, now);
    return generation;
}

auto Master::detach(std::uint64_t volume, std::uint64_t attachment_id, Time now)
    -> std::expected<void, Error> {
    auto r = live(volume);
    if (!r) {
        return std::unexpected(r.error());
    }
    Volume& v = **r;
    const auto it =
        std::ranges::find(v.attachments, attachment_id, &proto::VolumeAttachment::attachment_id);
    if (it == v.attachments.end()) {
        return std::unexpected(Error::unknown_attachment);
    }
    const proto::VolumeAttachment gone = *it;
    v.attachments.erase(it);
    v.retired[gone.generation] = v.epoch + 1;
    commit(v, now, {gone.server_id});
    return {};
}

auto Master::generation_fenced(std::uint64_t volume, std::uint32_t generation) const -> bool {
    const Volume* v = this->volume(volume);
    if (v == nullptr) {
        return true;  // deleted: no replica serves it
    }
    const auto it = v->retired.find(generation);
    if (it == v->retired.end()) {
        return false;
    }
    // Every member that could still serve it has applied the epoch
    // without it.
    return std::ranges::all_of(v->members, [&](const Member& m) {
        return (m.role != ReplicaRole::primary && m.role != ReplicaRole::leaving) ||
               m.applied_epoch >= it->second;
    });
}

auto Master::resize(std::uint64_t volume, std::uint64_t capacity_blocks, Time now)
    -> std::expected<void, Error> {
    auto r = live(volume);
    if (!r) {
        return std::unexpected(r.error());
    }
    Volume& v = **r;
    if (capacity_blocks <= v.spec.capacity_blocks) {
        return std::unexpected(Error::shrink);
    }
    if (capacity_blocks > std::numeric_limits<std::uint64_t>::max() / v.spec.block_size) {
        return std::unexpected(Error::bad_spec);
    }
    v.spec.capacity_blocks = capacity_blocks;
    commit(v, now);
    return {};
}

auto Master::set_qos(std::uint64_t volume, const proto::VolumeQos& qos, Time now)
    -> std::expected<void, Error> {
    auto r = live(volume);
    if (!r) {
        return std::unexpected(r.error());
    }
    if (!valid_qos(qos)) {
        return std::unexpected(Error::bad_spec);
    }
    (*r)->qos = qos;
    commit(**r, now);
    return {};
}

auto Master::enable_io(std::uint64_t volume, Time now) -> std::expected<void, Error> {
    auto r = live(volume);
    if (!r) {
        return std::unexpected(r.error());
    }
    Volume& v = **r;
    if (!suspended(v) || (v.flags & proto::replica_flags::impaired) == 0) {
        return std::unexpected(Error::not_suspended);
    }
    // The most up-to-date replica that can be reached, wherever it is.
    struct Pick {
        std::uint64_t server{0};
        std::uint32_t gen{0};
        std::uint64_t seq{0};
    };
    std::optional<Pick> best;
    auto consider = [&](std::uint64_t server, std::uint32_t gen, std::uint64_t seq) {
        if (server_up(server) &&
            (!best || seq > best->seq || (seq == best->seq && server < best->server))) {
            best = Pick{.server = server, .gen = gen, .seq = seq};
        }
    };
    for (const auto& m : v.members) {
        consider(m.server_id, m.replica_gen, m.last_seq);
    }
    for (const auto& a : v.away) {
        consider(a.server_id, a.replica_gen, a.last_seq);
    }
    if (!best) {
        return std::unexpected(Error::no_candidate);
    }
    // Everything else diverged from it: delete and rebuild from it.
    std::vector<std::uint64_t> removed;
    for (const auto& m : v.members) {
        if (m.server_id != best->server) {
            delete_replica(v, m.server_id, m.replica_gen, now);
            removed.push_back(m.server_id);
        }
    }
    for (const auto& a : v.away) {
        if (a.server_id != best->server) {
            delete_replica(v, a.server_id, a.replica_gen, now);
        }
    }
    v.members.clear();
    v.away.clear();
    v.move.reset();
    add_member(v, {.server_id = best->server,
                   .role = ReplicaRole::primary,
                   .replica_gen = best->gen,
                   .applied_epoch = 0,
                   .last_seq = best->seq,
                   .replacement = false});
    v.flags &= ~(proto::replica_flags::io_suspended | proto::replica_flags::impaired);
    v.loss_possible = true;
    v.failover = false;
    v.lease_acked.reset();
    commit(v, now, removed);
    return {};
}

auto Master::move_replica(std::uint64_t volume, std::uint64_t from, std::uint64_t to, Time now)
    -> std::expected<void, Error> {
    auto r = live(volume);
    if (!r) {
        return std::unexpected(r.error());
    }
    if (to != 0 && !_servers.contains(to)) {
        return std::unexpected(Error::unknown_server);
    }
    return start_move(**r, from, to, now);
}

auto Master::start_move(Volume& v, std::uint64_t from, std::uint64_t to, Time now)
    -> std::expected<void, Error> {
    if (v.move) {
        return std::unexpected(Error::busy);
    }
    const Member* source = member_on(v, from);
    if (source == nullptr || !in_sync(*source)) {
        return std::unexpected(Error::not_member);
    }
    if (primary_of(v) == nullptr || suspended(v) || v.failover) {
        return std::unexpected(Error::suspended);
    }
    if (v.members.size() >= proto::max_replica_members) {
        return std::unexpected(Error::busy);
    }
    std::vector<std::uint64_t> keep;
    std::vector<std::uint64_t> exclude{from};
    for (const auto& m : v.members) {
        if (m.server_id != from) {
            keep.push_back(m.server_id);
        }
    }
    for (const auto& a : v.away) {
        exclude.push_back(a.server_id);
    }
    const auto target = place(bytes_of(v.spec), 1, keep, exclude, to);
    if (!target) {
        return std::unexpected(Error::no_placement);
    }
    add_member(v, {.server_id = target->front(),
                   .role = ReplicaRole::joining,
                   .replica_gen = v.next_replica_gen++,
                   .applied_epoch = 0,
                   .last_seq = 0,
                   .replacement = false});
    v.move = Move{
        .from = from, .to = target->front(), .handing_over = false, .demotion_confirmed = false};
    commit(v, now);
    return {};
}

// ---- membership changes ----------------------------------------------------

auto Master::lease_expired(const Volume& v, Time now) const -> bool {
    if (!v.lease_acked) {
        return true;
    }
    const auto wait = Time{static_cast<Time::rep>(_timing.lease_ms) *
                           (percent + _timing.lease_margin_pct) / percent};
    return now >= *v.lease_acked + wait;
}

auto Master::drop_member(Volume& v, std::uint64_t server, Time now) -> void {
    Member* m = member_on(v, server);
    if (m == nullptr || m->role == ReplicaRole::primary) {
        return;  // primaries fail over instead
    }
    if (m->role == ReplicaRole::leaving) {
        return;  // a handover's source: tick finishes it when the lease is out
    }
    v.away.push_back({.server_id = server,
                      .replica_gen = m->replica_gen,
                      .last_seq = m->last_seq,
                      .since = now});
    remove_member(v, server);
    uploader_lost(v.spec.volume_id, server);
    if (v.move && v.move->to == server) {
        v.move.reset();  // the target is gone; the source stays
    } else if (v.move && v.move->from == server) {
        if (Member* t = member_on(v, v.move->to); t != nullptr) {
            t->replacement = true;  // now an ordinary rebuild
        }
        v.move.reset();
    }
    commit(v, now, {server});
}

auto Master::confirm_failover(Volume& v, Time /*now*/) -> void {
    if (!suspended(v)) {
        v.failover = true;  // no more lease acknowledgements for it
    }
}

auto Master::fail_over(Volume& v, Time now) -> void {
    Member* old = primary_of(v);
    v.failover = false;
    v.lease_acked.reset();
    if (old == nullptr) {
        return;
    }
    // The in-sync secondary with the highest reported sequence: every
    // in-sync member holds every acknowledged write.
    Member* best = nullptr;
    for (auto& m : v.members) {
        if (m.role == ReplicaRole::secondary && server_up(m.server_id) &&
            (best == nullptr || m.last_seq > best->last_seq)) {
            best = &m;
        }
    }
    if (best == nullptr) {
        // Nothing in sync survives: keep the listing, stop I/O (6.8).
        v.flags |= proto::replica_flags::io_suspended | proto::replica_flags::impaired;
        v.move.reset();
        commit(v, now);
        return;
    }
    const std::uint64_t old_server = old->server_id;
    v.away.push_back({.server_id = old_server,
                      .replica_gen = old->replica_gen,
                      .last_seq = old->last_seq,
                      .since = now});
    best->role = ReplicaRole::primary;
    remove_member(v, old_server);
    uploader_lost(v.spec.volume_id, old_server);
    if (v.move && (v.move->from == old_server || v.move->to == best->server_id)) {
        v.move.reset();
    }
    commit(v, now, {old_server});
}

auto Master::promote_joined(Volume& v, Member& m, Time now) -> void {
    m.role = ReplicaRole::secondary;
    m.replacement = false;
    const std::uint64_t joined = m.server_id;
    commit(v, now);
    if (!v.move || v.move->to != joined) {
        return;
    }
    Member* source = member_on(v, v.move->from);
    if (source == nullptr) {
        v.move.reset();
        return;
    }
    if (source->role == ReplicaRole::secondary) {
        const std::uint64_t from = source->server_id;
        const std::uint32_t gen = source->replica_gen;
        remove_member(v, from);
        v.move.reset();
        commit(v, now, {from});
        delete_replica(v, from, gen, now);
        return;
    }
    // A primary hands over: it leaves (no primary in this epoch, so I/O
    // waits), drains, and confirms; or its lease runs out (8.2).
    source->role = ReplicaRole::leaving;
    v.flags |= proto::replica_flags::io_suspended;
    v.move->handing_over = true;
    commit(v, now);
}

auto Master::finish_handover(Volume& v, Time now) -> void {
    Member* source = member_on(v, v.move->from);
    Member* target = member_on(v, v.move->to);
    v.move.reset();
    v.lease_acked.reset();
    if ((v.flags & proto::replica_flags::impaired) == 0) {
        v.flags &= ~proto::replica_flags::io_suspended;
    }
    if (target == nullptr || target->role != ReplicaRole::secondary) {
        if (source != nullptr) {
            source->role = ReplicaRole::primary;  // nowhere to go: stay
        }
        commit(v, now);
        return;
    }
    target->role = ReplicaRole::primary;
    if (source == nullptr) {
        commit(v, now);
        return;
    }
    const std::uint64_t from = source->server_id;
    const std::uint32_t gen = source->replica_gen;
    remove_member(v, from);
    commit(v, now, {from});
    delete_replica(v, from, gen, now);
}

auto Master::server_lost(std::uint64_t server, Time now) -> void {
    _servers.at(server).up = false;
    for (auto& [id, v] : _volumes) {
        const Member* m = member_on(v, server);
        if (m == nullptr) {
            continue;
        }
        if (m->role == ReplicaRole::primary) {
            confirm_failover(v, now);
        } else if (m->role != ReplicaRole::leaving) {
            drop_member(v, server, now);
        }
    }
}

auto Master::server_returned(std::uint64_t server, Time now) -> void {
    _servers.at(server).up = true;
    const Time window{static_cast<Time::rep>(_timing.resync_window_s) * ms_per_s};
    for (auto& [id, v] : _volumes) {
        const auto it = std::ranges::find(v.away, server, &AwayReplica::server_id);
        if (it == v.away.end() || suspended(v)) {
            continue;  // a suspended volume keeps it for enable_io
        }
        const AwayReplica back = *it;
        v.away.erase(it);
        if (now - back.since > window) {
            delete_replica(v, server, back.replica_gen, now);
            continue;
        }
        std::vector<std::uint64_t> displaced;
        if (in_sync_count(v) + joining_count(v) >= v.spec.volume_class.replicas) {
            // A rebuild elsewhere started meanwhile: a partial resync of
            // the returning replica is cheaper (7.1-7.2).
            const auto r = std::ranges::find_if(v.members, [&](const Member& m) {
                return m.role == ReplicaRole::joining && m.replacement;
            });
            if (r == v.members.end()) {
                delete_replica(v, server, back.replica_gen, now);
                continue;
            }
            displaced.push_back(r->server_id);
            delete_replica(v, r->server_id, r->replica_gen, now);
            v.members.erase(r);
        }
        add_member(v, {.server_id = server,
                       .role = ReplicaRole::joining,
                       .replica_gen = back.replica_gen,
                       .applied_epoch = 0,
                       .last_seq = back.last_seq,
                       .replacement = false});
        commit(v, now, displaced);
    }
}

auto Master::schedule_rebuilds(Time now) -> void {
    std::vector<Volume*> short_of;
    for (auto& [id, v] : _volumes) {
        if (primary_of(v) != nullptr && !suspended(v) && !v.failover &&
            in_sync_count(v) + joining_count(v) < v.spec.volume_class.replicas) {
            short_of.push_back(&v);
        }
    }
    // Fewest in-sync replicas first, then class priority (7.5).
    std::ranges::sort(short_of, {}, [](const Volume* v) {
        return std::tuple{in_sync_count(*v), -static_cast<int>(v->spec.volume_class.priority),
                          v->spec.volume_id};
    });
    for (Volume* v : short_of) {
        // A replica out of the set on a server that still reports: resync
        // it in place rather than copy everything elsewhere (7.1-7.2).
        for (auto it = v->away.begin(); it != v->away.end();) {
            const auto srv = _servers.find(it->server_id);
            if (joining_total() < _limits.rebuilds &&
                in_sync_count(*v) + joining_count(*v) < v->spec.volume_class.replicas &&
                v->members.size() < proto::max_replica_members && srv != _servers.end() &&
                srv->second.up && !srv->second.draining &&
                now - it->since >= _timing.rejoin_after &&
                joining_on(it->server_id) < _limits.rebuilds_per_server) {
                add_member(*v, {.server_id = it->server_id,
                                .role = ReplicaRole::joining,
                                .replica_gen = it->replica_gen,
                                .applied_epoch = 0,
                                .last_seq = it->last_seq,
                                .replacement = false});
                it = v->away.erase(it);
                commit(*v, now);
            } else {
                ++it;
            }
        }
        while (joining_total() < _limits.rebuilds &&
               in_sync_count(*v) + joining_count(*v) < v->spec.volume_class.replicas &&
               v->members.size() < proto::max_replica_members) {
            std::vector<std::uint64_t> keep;
            std::vector<std::uint64_t> exclude;
            for (const auto& m : v->members) {
                keep.push_back(m.server_id);
            }
            for (const auto& a : v->away) {
                exclude.push_back(a.server_id);
            }
            const auto target = place(bytes_of(v->spec), 1, keep, exclude);
            if (!target) {
                break;
            }
            add_member(*v, {.server_id = target->front(),
                            .role = ReplicaRole::joining,
                            .replica_gen = v->next_replica_gen++,
                            .applied_epoch = 0,
                            .last_seq = 0,
                            .replacement = true});
            commit(*v, now);
        }
    }
}

auto Master::schedule_drains(Time now) -> void {
    std::size_t moving = static_cast<std::size_t>(
        std::ranges::count_if(_volumes, [](const auto& kv) { return kv.second.move.has_value(); }));
    for (auto& [sid, s] : _servers) {
        if (!s.draining) {
            continue;
        }
        for (auto& [vid, v] : _volumes) {
            // Replicas out of the set are not worth keeping on it.
            for (auto it = v.away.begin(); it != v.away.end();) {
                if (it->server_id == sid && !suspended(v)) {
                    delete_replica(v, sid, it->replica_gen, now);
                    it = v.away.erase(it);
                } else {
                    ++it;
                }
            }
            const Member* m = member_on(v, sid);
            if (moving >= _limits.drain_moves || m == nullptr || !in_sync(*m) || v.move) {
                continue;
            }
            if (start_move(v, sid, 0, now)) {
                ++moving;
            }
        }
    }
}

auto Master::uploader_lost(std::uint64_t volume, std::uint64_t server) -> void {
    for (auto& [id, s] : _snapshots) {
        if (s.status != SnapshotStatus::uploading) {
            continue;
        }
        const auto part = std::ranges::find(s.parts, volume, &SnapshotPart::volume_id);
        if (part != s.parts.end() && part->uploader == server && !part->manifest) {
            s.status = SnapshotStatus::failed;  // the frozen clone went with it
            for (const auto& p : s.parts) {
                _lineages[p.lineage_id].gc_wanted = true;
            }
        }
    }
    run_gc();
}

// ---- reports ---------------------------------------------------------------

auto Master::on_report(const proto::Report& report, Time now) -> void {
    const auto it = _servers.find(report.server_id);
    if (it == _servers.end()) {
        return;  // not a storage server: compute-side reports go elsewhere
    }
    it->second.last_seen = now;
    if (!it->second.up) {
        server_returned(report.server_id, now);
    }
    const std::uint64_t server = report.server_id;
    if (const auto* rs = std::get_if<proto::ReplicaStatus>(&report.body)) {
        for (const auto& e : rs->entries) {
            on_status(server, e, now);
        }
    } else if (const auto* f = std::get_if<proto::VolumeFault>(&report.body)) {
        on_fault(server, *f, now);
    } else if (const auto* d = std::get_if<proto::DemotionConfirmed>(&report.body)) {
        on_demotion(server, *d, now);
    } else if (const auto* o = std::get_if<proto::OpOutcome>(&report.body)) {
        on_outcome(server, *o, now);
    } else if (const auto* p = std::get_if<proto::SnapshotProgress>(&report.body)) {
        on_progress(server, *p, now);
    }
}

auto Master::on_status(std::uint64_t server, const proto::ReplicaStatusEntry& e, Time now) -> void {
    Volume* v = find(e.volume_id);
    if (v == nullptr) {
        return;
    }
    Member* m = member_on(*v, server);
    if (m == nullptr || m->replica_gen != e.replica_gen) {
        return;
    }
    m->applied_epoch = std::max(m->applied_epoch, e.epoch);
    m->last_seq = e.last_seq;
    if (e.epoch != v->epoch) {
        return;
    }
    // The primary's status is its lease request (design "Epochs, leases").
    if (m->role == ReplicaRole::primary && e.role == ReplicaRole::primary && !v->failover &&
        !suspended(*v)) {
        v->lease_acked = now;
        _transport->grant_lease(server, v->spec.volume_id, v->epoch);
    }
    if (m->role == ReplicaRole::joining && e.role == ReplicaRole::joining &&
        e.state == proto::ReplicaState::in_sync) {
        promote_joined(*v, *m, now);
    }
}

auto Master::on_fault(std::uint64_t server, const proto::VolumeFault& f, Time now) -> void {
    Volume* v = find(f.volume_id);
    if (v == nullptr) {
        return;
    }
    if (f.kind == proto::VolumeFaultKind::stale_epoch) {
        // Someone is behind: send it the current config.
        const bool known =
            member_on(*v, f.suspect) != nullptr ||
            std::ranges::find(v->attachments, f.suspect, &proto::VolumeAttachment::server_id) !=
                v->attachments.end();
        if (known && f.epoch <= v->epoch) {
            publish(*v, f.suspect);
        }
        return;
    }
    if (f.epoch != v->epoch) {
        return;  // about an epoch already superseded
    }
    const Member* reporter = member_on(*v, server);
    const Member* primary = primary_of(*v);
    switch (f.kind) {
        case proto::VolumeFaultKind::member_timeout:
            if (primary != nullptr && primary->server_id == server && f.suspect != server) {
                drop_member(*v, f.suspect, now);
            }
            break;
        case proto::VolumeFaultKind::primary_timeout:
            if (primary == nullptr || primary->server_id != f.suspect) {
                break;
            }
            v->primary_suspects.insert(server);
            if (!v->suspected_at) {
                v->suspected_at = now;
            }
            // An initiator alone may be the one partitioned; a member's
            // word (or the server's silence, in tick) confirms.
            if (f.reporter == proto::FaultReporter::hold && reporter != nullptr &&
                reporter->server_id != f.suspect) {
                confirm_failover(*v, now);
            }
            break;
        case proto::VolumeFaultKind::checksum_unrepairable:
        case proto::VolumeFaultKind::media_error:
            if (reporter == nullptr) {
                break;
            }
            if (reporter->role == ReplicaRole::primary) {
                confirm_failover(*v, now);
            } else {
                drop_member(*v, server, now);
            }
            break;
        case proto::VolumeFaultKind::lease_lost:
        case proto::VolumeFaultKind::stale_epoch:
            break;
    }
}

auto Master::on_demotion(std::uint64_t server, const proto::DemotionConfirmed& d, Time now)
    -> void {
    Volume* v = find(d.volume_id);
    if (v == nullptr || !v->move || !v->move->handing_over || v->move->from != server ||
        d.epoch != v->epoch) {
        return;
    }
    v->move->demotion_confirmed = true;
    finish_handover(*v, now);
}

auto Master::on_outcome(std::uint64_t /*server*/, const proto::OpOutcome& o, Time now) -> void {
    const auto it = _ops.find(o.op_id);
    if (it == _ops.end() || it->second.op.volume_id != o.volume_id) {
        return;  // a duplicate, or not ours
    }
    const proto::VolumeOp op = it->second.op;
    _ops.erase(it);
    if (const auto* prep = std::get_if<proto::SnapshotPrepare>(&op.args)) {
        const auto s = _snapshots.find(prep->cut_id);
        if (s == _snapshots.end() || s->second.status != SnapshotStatus::preparing) {
            return;
        }
        if (o.status != proto::OpStatus::ok) {
            abort_snapshot(s->second, now);
            return;
        }
        const auto part = std::ranges::find(s->second.parts, o.volume_id, &SnapshotPart::volume_id);
        if (part != s->second.parts.end()) {
            part->prepared = true;
            part->cut_seq = o.detail;
        }
        if (std::ranges::all_of(s->second.parts, &SnapshotPart::prepared)) {
            commit_snapshot(s->second, now);
        }
    } else if (const auto* up = std::get_if<proto::SnapshotUpload>(&op.args)) {
        const auto s = _snapshots.find(up->cut_id);
        if (s != _snapshots.end() && o.status != proto::OpStatus::ok) {
            s->second.status = SnapshotStatus::failed;
            for (const auto& p : s->second.parts) {
                _lineages[p.lineage_id].gc_wanted = true;  // sweep what it left
            }
            run_gc();
        }
    }
}

auto Master::on_progress(std::uint64_t server, const proto::SnapshotProgress& p, Time /*now*/)
    -> void {
    const auto s = _snapshots.find(p.cut_id);
    if (s == _snapshots.end() || s->second.status != SnapshotStatus::uploading) {
        return;
    }
    Snapshot& snap = s->second;
    const auto part = std::ranges::find(snap.parts, p.volume_id, &SnapshotPart::volume_id);
    if (part == snap.parts.end() || part->uploader != server) {
        return;
    }
    if (p.state == proto::SnapshotState::failed) {
        snap.status = SnapshotStatus::failed;
        for (const auto& q : snap.parts) {
            _lineages[q.lineage_id].gc_wanted = true;
        }
        run_gc();
        return;
    }
    if (p.state != proto::SnapshotState::completed) {
        return;
    }
    part->manifest = p.manifest_name;
    if (Volume* v = find(p.volume_id); v != nullptr) {
        v->last_manifest = p.manifest_name;
    }
    if (std::ranges::all_of(snap.parts,
                            [](const SnapshotPart& q) { return q.manifest.has_value(); })) {
        snap.status = SnapshotStatus::completed;
    }
    run_gc();
}

// ---- snapshots -------------------------------------------------------------

auto Master::create_snapshot(std::uint64_t snapshot_id, std::span<const std::uint64_t> volumes,
                             std::uint32_t store_id, Time now) -> std::expected<void, Error> {
    if (snapshot_id == 0 || volumes.empty()) {
        return std::unexpected(Error::bad_spec);
    }
    if (_snapshots.contains(snapshot_id)) {
        return std::unexpected(Error::duplicate_snapshot);
    }
    Snapshot snap{.snapshot_id = snapshot_id,
                  .store_id = store_id,
                  .status = SnapshotStatus::preparing,
                  .started = now,
                  .parts = {}};
    for (const auto id : volumes) {
        const Volume* v = volume(id);
        if (v == nullptr) {
            return std::unexpected(Error::unknown_volume);
        }
        if (std::ranges::find(snap.parts, id, &SnapshotPart::volume_id) != snap.parts.end()) {
            return std::unexpected(Error::bad_spec);
        }
        if (primary_of(*v) == nullptr || suspended(*v) || v->failover) {
            return std::unexpected(Error::suspended);
        }
        for (const auto& [sid, other] : _snapshots) {
            if ((other.status == SnapshotStatus::preparing ||
                 other.status == SnapshotStatus::uploading) &&
                std::ranges::find(other.parts, id, &SnapshotPart::volume_id) != other.parts.end()) {
                return std::unexpected(Error::busy);
            }
        }
        snap.parts.push_back({.volume_id = id,
                              .lineage_id = v->spec.lineage_id,
                              .prepared = false,
                              .cut_seq = 0,
                              .uploader = 0,
                              .upload_sent = false,
                              .manifest = std::nullopt});
    }
    for (const auto& part : snap.parts) {
        const Volume& v = *volume(part.volume_id);
        send_op(
            v, primary_of(v)->server_id,
            proto::SnapshotPrepare{.cut_id = snapshot_id, .timeout_ms = _timing.prepare_timeout_ms},
            now);
    }
    _snapshots.emplace(snapshot_id, std::move(snap));
    return {};
}

auto Master::commit_snapshot(Snapshot& s, Time now) -> void {
    std::vector<std::pair<const Volume*, const Member*>> sets;
    for (const auto& part : s.parts) {
        const Volume* v = volume(part.volume_id);
        const Member* p = v == nullptr ? nullptr : primary_of(*v);
        if (p == nullptr) {
            abort_snapshot(s, now);
            return;
        }
        sets.emplace_back(v, p);
    }
    for (std::size_t i = 0; i < s.parts.size(); ++i) {
        SnapshotPart& part = s.parts[i];
        const Volume& v = *sets[i].first;
        // A secondary uploads, to spare the primary; the primary if alone.
        const auto sec = std::ranges::find(v.members, ReplicaRole::secondary, &Member::role);
        part.uploader = sec != v.members.end() ? sec->server_id : sets[i].second->server_id;
        for (const auto& m : v.members) {
            if (in_sync(m)) {
                send_op(v, m.server_id,
                        proto::SnapshotCommit{.cut_id = s.snapshot_id, .uploader = part.uploader},
                        now);
            }
        }
    }
    s.status = SnapshotStatus::uploading;
    send_uploads(now);
}

auto Master::abort_snapshot(Snapshot& s, Time now) -> void {
    for (const auto& part : s.parts) {
        const Volume* v = volume(part.volume_id);
        if (v != nullptr && primary_of(*v) != nullptr) {
            send_op(*v, primary_of(*v)->server_id, proto::SnapshotAbort{.cut_id = s.snapshot_id},
                    now);
        }
    }
    s.status = SnapshotStatus::failed;
}

auto Master::send_uploads(Time now) -> void {
    for (auto& [id, s] : _snapshots) {
        if (s.status != SnapshotStatus::uploading) {
            continue;
        }
        for (auto& part : s.parts) {
            const Volume* v = volume(part.volume_id);
            if (part.upload_sent || v == nullptr || _lineages[part.lineage_id].gc_running) {
                continue;  // a sweep of the lineage runs: uploads wait
            }
            send_op(*v, part.uploader,
                    proto::SnapshotUpload{
                        .cut_id = s.snapshot_id,
                        .store_id = s.store_id,
                        .parent_manifest = v->last_manifest.value_or(proto::ManifestName{})},
                    now);
            part.upload_sent = true;
        }
    }
}

auto Master::newest_manifest(std::uint64_t volume) const -> std::optional<proto::ManifestName> {
    std::optional<proto::ManifestName> best;
    Time newest{std::numeric_limits<Time::rep>::min()};
    for (const auto& [id, s] : _snapshots) {
        if (s.status != SnapshotStatus::completed || s.started < newest) {
            continue;
        }
        const auto part = std::ranges::find(s.parts, volume, &SnapshotPart::volume_id);
        if (part != s.parts.end() && part->manifest) {
            best = part->manifest;
            newest = s.started;
        }
    }
    return best;
}

auto Master::delete_snapshot(std::uint64_t snapshot_id, Time now) -> std::expected<void, Error> {
    const auto it = _snapshots.find(snapshot_id);
    if (it == _snapshots.end()) {
        return std::unexpected(Error::unknown_snapshot);
    }
    if (it->second.status == SnapshotStatus::preparing) {
        abort_snapshot(it->second, now);
    }
    const Snapshot gone = std::move(it->second);
    _snapshots.erase(it);
    for (const auto& part : gone.parts) {
        _lineages[part.lineage_id].gc_wanted = true;
        if (Volume* v = find(part.volume_id);
            v != nullptr && part.manifest && v->last_manifest == part.manifest) {
            // Its chunks may be swept: the next upload diffs against an
            // older manifest, or uploads in full.
            v->last_manifest = newest_manifest(part.volume_id);
        }
    }
    run_gc();
    for (const auto& part : gone.parts) {
        maybe_erase(part.lineage_id);
    }
    return {};
}

auto Master::run_gc() -> void {
    for (auto& [lineage, state] : _lineages) {
        if (!state.gc_wanted || state.gc_running) {
            continue;
        }
        std::vector<proto::ManifestName> live;
        bool uploading = false;
        for (const auto& [id, s] : _snapshots) {
            for (const auto& part : s.parts) {
                if (part.lineage_id != lineage) {
                    continue;
                }
                if (s.status == SnapshotStatus::preparing ||
                    (s.status == SnapshotStatus::uploading && !part.manifest)) {
                    uploading = true;
                }
                if (part.manifest && s.status != SnapshotStatus::failed) {
                    live.push_back(*part.manifest);
                }
            }
        }
        if (uploading) {
            continue;  // one at a time: the sweep waits for the uploads
        }
        state.gc_wanted = false;
        state.gc_running = true;
        _transport->sweep_lineage(lineage, live);
    }
}

auto Master::gc_finished(std::uint64_t lineage, Time now) -> void {
    const auto it = _lineages.find(lineage);
    if (it == _lineages.end() || !it->second.gc_running) {
        return;
    }
    it->second.gc_running = false;
    send_uploads(now);
    run_gc();
    maybe_erase(lineage);
}

auto Master::maybe_erase(std::uint64_t lineage) -> void {
    if (_erased.contains(lineage)) {
        return;
    }
    if (std::ranges::any_of(_volumes,
                            [&](const auto& kv) { return kv.second.spec.lineage_id == lineage; })) {
        return;
    }
    for (const auto& [id, s] : _snapshots) {
        if (std::ranges::find(s.parts, lineage, &SnapshotPart::lineage_id) != s.parts.end()) {
            return;
        }
    }
    const auto it = _lineages.find(lineage);
    if (it != _lineages.end() && (it->second.gc_running || it->second.gc_wanted)) {
        return;  // sweep its objects first; the key goes after
    }
    _lineages.erase(lineage);
    _erased.insert(lineage);
    _transport->destroy_lineage_key(lineage);
}

// ---- time ------------------------------------------------------------------

auto Master::tick(Time now) -> void {
    for (auto& [id, s] : _servers) {
        if (s.up && now - s.last_seen > _timing.server_silence) {
            server_lost(id, now);
        }
    }
    const Time window{static_cast<Time::rep>(_timing.resync_window_s) * ms_per_s};
    for (auto& [id, v] : _volumes) {
        if (!v.failover && v.suspected_at && now - *v.suspected_at > _timing.suspicion_ttl) {
            v.primary_suspects.clear();  // unconfirmed: the primary is fine
            v.suspected_at.reset();
        }
        if (v.failover && lease_expired(v, now)) {
            fail_over(v, now);
        }
        if (v.move && v.move->handing_over && lease_expired(v, now)) {
            finish_handover(v, now);
        }
        if (!suspended(v)) {
            for (auto it = v.away.begin(); it != v.away.end();) {
                if (now - it->since > window) {
                    delete_replica(v, it->server_id, it->replica_gen, now);
                    it = v.away.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (now - v.published >= _timing.retry) {
            bool resent = false;
            for (const auto& m : v.members) {
                if (m.applied_epoch < v.epoch && server_up(m.server_id)) {
                    publish(v, m.server_id);
                    resent = true;
                }
            }
            if (resent) {
                v.published = now;
            }
        }
    }
    for (auto& [op_id, p] : _ops) {
        if (now - p.sent >= _timing.retry && server_up(p.op.server_id)) {
            _transport->send_op(p.op);
            p.sent = now;
        }
    }
    const Time prepare{static_cast<Time::rep>(_timing.prepare_timeout_ms)};
    for (auto& [id, s] : _snapshots) {
        if (s.status == SnapshotStatus::preparing && now - s.started >= prepare) {
            abort_snapshot(s, now);
        }
    }
    schedule_drains(now);
    schedule_rebuilds(now);
    run_gc();
}

}  // namespace ak::hold::master
