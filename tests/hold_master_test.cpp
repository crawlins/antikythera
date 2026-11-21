// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 4: the controller reference model,
// one test per rule. Placement across failure domains (Requirement 5.2);
// epochs and publish order (6.2); attachment generations and fencing
// (6.4, 6.9); leases (6.3); secondary and primary failure, confirmation
// and the no-in-sync-replica case (6.5, 6.6, 6.8); rebuild, partial resync
// and ordering (7.1, 7.2, 7.5); moves, primary handover and drain (8.1-
// 8.5); snapshot cuts, uploads and GC (11.2, 11.8); crypto-erase (12.4).
// Every config the master sends must pass the ReplicaConfig decoder's
// rules, and epochs per recipient never go back.

#define BOOST_TEST_MODULE hold_master_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <ostream>
#include <span>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "hold/master/master.hpp"
#include "proto/replica_config.hpp"
#include "proto/report.hpp"
#include "proto/volume_op.hpp"
#include "test_support.hpp"

namespace ak::hold::master {
auto operator<<(std::ostream& os, Error e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, SnapshotStatus s) -> std::ostream& {
    return os << static_cast<int>(s);
}
}  // namespace ak::hold::master

namespace {

namespace m = ak::hold::master;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using m::Time;
using proto::ReplicaRole;

constexpr std::uint64_t gib = 1ULL << 30U;
constexpr std::uint64_t blocks_1g = gib / proto::block_size_4096;
constexpr std::uint16_t hold_port = 7300;
constexpr std::uint64_t compute = 0xC0;  // a compute server's ID

class Recorder final : public m::Transport {
public:
    auto send_config(const proto::ReplicaConfig& config) -> void override {
        // Encodes and decodes under the decoder's rules, as the role would.
        auto signed_copy = config;
        signed_copy.key_id = 1;  // the transport would sign it
        const auto bytes = proto::encode_replica_config(signed_copy);
        BOOST_TEST_REQUIRE(bytes.has_value(), "config refused: server "
                                                  << config.server_id << " epoch " << config.epoch);
        const auto back = proto::decode_replica_config(*bytes);
        BOOST_TEST_REQUIRE(back.has_value());
        BOOST_TEST((*back == signed_copy));
        auto& last = _epochs[{config.server_id, config.volume_id}];
        BOOST_TEST(config.epoch >= last);
        last = config.epoch;
        configs.push_back(config);
    }
    auto send_op(const proto::VolumeOp& op) -> void override {
        auto signed_copy = op;
        signed_copy.key_id = 1;
        BOOST_TEST(proto::encode_volume_op(signed_copy).has_value());
        ops.push_back(op);
    }
    auto grant_lease(std::uint64_t server, std::uint64_t volume, std::uint64_t epoch)
        -> void override {
        leases.emplace_back(server, volume, epoch);
    }
    auto sweep_lineage(std::uint64_t lineage, std::span<const proto::ManifestName> live)
        -> void override {
        sweeps.emplace_back(lineage, std::vector<proto::ManifestName>(live.begin(), live.end()));
    }
    auto destroy_lineage_key(std::uint64_t lineage) -> void override {
        destroyed.push_back(lineage);
    }

    auto clear() -> void {
        configs.clear();
        ops.clear();
        leases.clear();
    }
    // The ops of one kind, in order.
    template<typename Args> [[nodiscard]] auto ops_of() const -> std::vector<proto::VolumeOp> {
        std::vector<proto::VolumeOp> out;
        std::ranges::copy_if(ops, std::back_inserter(out), [](const proto::VolumeOp& o) {
            return std::holds_alternative<Args>(o.args);
        });
        return out;
    }

    std::vector<proto::ReplicaConfig> configs;
    std::vector<proto::VolumeOp> ops;
    std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>> leases;
    std::vector<std::pair<std::uint64_t, std::vector<proto::ManifestName>>> sweeps;
    std::vector<std::uint64_t> destroyed;

private:
    std::map<std::pair<std::uint64_t, std::uint64_t>, std::uint64_t> _epochs;
};

auto endpoint(std::uint64_t id) -> proto::StorageEndpoint {
    proto::StorageEndpoint e{};
    e[0] = std::byte{0xFD};
    e[15] = static_cast<std::byte>(id);
    return e;
}

auto manifest(std::uint8_t n) -> proto::ManifestName {
    proto::ManifestName name{};
    name[0] = std::byte{n};
    return name;
}

struct Rig {
    Recorder t;
    m::Master master;
    Time now{1000};
    std::uint64_t servers{0};

    explicit Rig(std::vector<std::uint32_t> racks, m::Limits limits = {},
                 std::uint64_t capacity = 100 * gib)
        : master{t, {}, limits}, servers{racks.size()} {
        for (std::size_t i = 0; i < racks.size(); ++i) {
            const std::uint64_t id = i + 1;
            BOOST_REQUIRE(master
                              .add_server({.server_id = id,
                                           .endpoint = endpoint(id),
                                           .port = hold_port,
                                           .rack = racks[i],
                                           .power = 0,
                                           .capacity_bytes = capacity},
                                          now)
                              .has_value());
        }
    }

    auto create(std::uint64_t volume, m::VolumeClass cls = m::general_class(),
                std::uint64_t lineage = 0, bool multi = false) -> const m::Volume& {
        auto r = master.create_volume({.volume_id = volume,
                                       .lineage_id = lineage == 0 ? volume : lineage,
                                       .capacity_blocks = blocks_1g,
                                       .block_size = proto::block_size_4096,
                                       .volume_class = cls,
                                       .multi_attach = multi,
                                       .source = {}},
                                      now);
        BOOST_REQUIRE(r.has_value());
        return *master.volume(volume);
    }
    [[nodiscard]] auto vol(std::uint64_t id) const -> const m::Volume& {
        const auto* v = master.volume(id);
        BOOST_REQUIRE(v != nullptr);
        return *v;
    }
    [[nodiscard]] auto primary(std::uint64_t id) const -> std::uint64_t {
        for (const auto& mem : vol(id).members) {
            if (mem.role == ReplicaRole::primary) {
                return mem.server_id;
            }
        }
        return 0;
    }
    [[nodiscard]] auto with_role(std::uint64_t id, ReplicaRole role) const
        -> std::vector<std::uint64_t> {
        std::vector<std::uint64_t> out;
        for (const auto& mem : vol(id).members) {
            if (mem.role == role) {
                out.push_back(mem.server_id);
            }
        }
        return out;
    }
    [[nodiscard]] auto gen_of(std::uint64_t id, std::uint64_t server) const -> std::uint32_t {
        for (const auto& mem : vol(id).members) {
            if (mem.server_id == server) {
                return mem.replica_gen;
            }
        }
        return 0;
    }

    auto report(std::uint64_t server, proto::ReportBody body) -> void {
        master.on_report({.server_id = server, .report_seq = 0, .body = std::move(body)}, now);
    }
    // replica_status from `server` about its replica of `volume`, at the
    // volume's current epoch unless told otherwise.
    auto status(std::uint64_t server, std::uint64_t volume, std::uint64_t seq = 0,
                std::optional<proto::ReplicaState> state = std::nullopt,
                std::optional<std::uint64_t> epoch = std::nullopt) -> void {
        const m::Volume& v = vol(volume);
        ReplicaRole role = ReplicaRole::secondary;
        for (const auto& mem : v.members) {
            if (mem.server_id == server) {
                role = mem.role;
            }
        }
        const auto st = state.value_or(role == ReplicaRole::joining ? proto::ReplicaState::joining
                                                                    : proto::ReplicaState::in_sync);
        report(server, proto::ReplicaStatus{.entries = {{.volume_id = volume,
                                                         .epoch = epoch.value_or(v.epoch),
                                                         .replica_gen = gen_of(volume, server),
                                                         .role = role,
                                                         .state = st,
                                                         .last_seq = seq,
                                                         .commit_seq = seq}}});
    }
    // Every member of `volume` reports the current epoch applied.
    auto all_status(std::uint64_t volume) -> void {
        const auto members = vol(volume).members;
        for (const auto& mem : members) {
            status(mem.server_id, volume);
        }
    }
    auto fault(std::uint64_t reporter, std::uint64_t volume, proto::VolumeFaultKind kind,
               std::uint64_t suspect, proto::FaultReporter who = proto::FaultReporter::hold)
        -> void {
        report(reporter, proto::VolumeFault{.volume_id = volume,
                                            .epoch = vol(volume).epoch,
                                            .suspect = suspect,
                                            .kind = kind,
                                            .reporter = who});
    }
    auto outcome(const proto::VolumeOp& op, proto::OpStatus status = proto::OpStatus::ok,
                 std::uint64_t detail = 0) -> void {
        report(op.server_id, proto::OpOutcome{.volume_id = op.volume_id,
                                              .op_id = op.op_id,
                                              .epoch = op.epoch,
                                              .detail = detail,
                                              .kind = proto::volume_op_kind(op.args),
                                              .status = status});
    }
    // Every server but `silent` says something (a down one comes back).
    auto heartbeat(std::uint64_t silent = 0) -> void {
        for (std::uint64_t s = 1; s <= servers; ++s) {
            if (s != silent) {
                report(s, proto::ReplicaStatus{});
            }
        }
    }
    // Time passes with every server but `silent` reporting, then a tick.
    auto advance(Time by, std::uint64_t silent = 0) -> void {
        now += by;
        heartbeat(silent);
        master.tick(now);
    }
};

auto lease_wait() -> Time {
    const m::Timing t;
    return Time{t.lease_ms * (100 + t.lease_margin_pct) / 100};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(placement)

BOOST_AUTO_TEST_CASE(replicas_land_in_distinct_failure_domains,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 1, 2, 3}};
    const auto& v = rig.create(10, m::provisioned_class());
    BOOST_REQUIRE(v.members.size() == 3U);
    BOOST_TEST(rig.with_role(10, ReplicaRole::primary).size() == 1U);
    // Servers 1 and 2 share rack 1: never both.
    const bool both = std::ranges::count_if(v.members, [](const m::Member& x) {
                          return x.server_id == 1 || x.server_id == 2;
                      }) == 2;
    BOOST_TEST(!both);
    BOOST_TEST(v.epoch == 1U);
}

BOOST_AUTO_TEST_CASE(refuses_what_cannot_honour_the_domains,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 1, 2}};
    auto r = rig.master.create_volume({.volume_id = 10,
                                       .lineage_id = 10,
                                       .capacity_blocks = blocks_1g,
                                       .volume_class = m::provisioned_class()},
                                      rig.now);
    BOOST_TEST(r.error() == m::Error::no_placement);
    // Two replicas fit (racks 1 and 2); nothing was half-created.
    BOOST_TEST(rig.master.volume(10) == nullptr);
    rig.create(11);
    // No room: a replica bigger than any server.
    r = rig.master.create_volume({.volume_id = 12,
                                  .lineage_id = 12,
                                  .capacity_blocks = 200 * blocks_1g,
                                  .volume_class = m::general_class()},
                                 rig.now);
    BOOST_TEST(r.error() == m::Error::no_placement);
}

BOOST_AUTO_TEST_CASE(depth_first_finds_what_greedy_misses,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Least-loaded order is 1, 2, 3; taking 1 and 2 (racks 1 and 2) leaves
    // nothing for a third. 1, 3, 4 works.
    Rig rig{{1, 2, 3, 2}};
    rig.create(5, m::general_class());  // loads servers 1 and 2
    const auto& v = rig.create(10, m::provisioned_class());
    BOOST_TEST(v.members.size() == 3U);
}

BOOST_AUTO_TEST_CASE(refuses_bad_specs, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    auto bad = [&](m::VolumeSpec s) {
        return rig.master.create_volume(s, rig.now).error() == m::Error::bad_spec;
    };
    const m::VolumeSpec ok{.volume_id = 1, .lineage_id = 1, .capacity_blocks = 8};
    auto s = ok;
    s.block_size = 1024;
    BOOST_TEST(bad(s));
    s = ok;
    s.volume_class.replicas = 1;
    BOOST_TEST(bad(s));
    s = ok;
    s.multi_attach = true;  // general does not allow it
    BOOST_TEST(bad(s));
    s = ok;
    s.volume_class.qos.burst_iops = 1;
    BOOST_TEST(bad(s));
    s = ok;
    s.lineage_id = 0;
    BOOST_TEST(bad(s));
    BOOST_TEST(rig.master.create_volume(ok, rig.now).has_value());
    BOOST_TEST(rig.master.create_volume(ok, rig.now).error() == m::Error::duplicate_volume);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(epochs_and_attachments)

BOOST_AUTO_TEST_CASE(publishes_to_members_then_attachments,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    BOOST_TEST(rig.t.configs.size() == 2U);  // one per member
    rig.t.clear();
    const auto gen = rig.master.attach(10, 0xA1, compute, proto::AttachMode::rw, rig.now);
    BOOST_REQUIRE(gen.has_value());
    BOOST_TEST(*gen == 1U);
    BOOST_REQUIRE(rig.t.configs.size() == 3U);
    BOOST_TEST(rig.t.configs[2].server_id == compute);  // after the members
    for (const auto& c : rig.t.configs) {
        BOOST_TEST(c.epoch == 2U);
        BOOST_TEST(c.attachments.size() == 1U);
    }
    BOOST_TEST(rig.master.resize(10, blocks_1g, rig.now).error() == m::Error::shrink);
    BOOST_TEST(rig.master.resize(10, 2 * blocks_1g, rig.now).has_value());
    BOOST_TEST(rig.vol(10).epoch == 3U);
    BOOST_TEST(rig.master.set_qos(10, {.iops = 1}, rig.now).error() == m::Error::bad_spec);
    BOOST_TEST(rig.master.set_qos(10, {1, 1, 1, 1}, rig.now).has_value());
    BOOST_TEST(rig.vol(10).epoch == 4U);
}

BOOST_AUTO_TEST_CASE(attachment_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    BOOST_TEST(rig.master.attach(10, 1, compute, proto::AttachMode::rw, rig.now).has_value());
    BOOST_TEST(rig.master.attach(10, 2, compute, proto::AttachMode::rw, rig.now).error() ==
               m::Error::multi_attach_needed);
    BOOST_TEST(rig.master.attach(10, 1, compute, proto::AttachMode::ro, rig.now).error() ==
               m::Error::duplicate_attachment);
    for (std::uint64_t a = 2; a <= proto::max_volume_attachments; ++a) {
        BOOST_TEST(
            rig.master.attach(10, a, compute + a, proto::AttachMode::ro, rig.now).has_value());
    }
    BOOST_TEST(rig.master.attach(10, 99, compute, proto::AttachMode::ro, rig.now).error() ==
               m::Error::attachment_limit);
    BOOST_TEST(rig.master.delete_volume(10, rig.now).error() == m::Error::attached);

    rig.create(11, m::provisioned_class(), 0, true);
    BOOST_TEST(rig.master.attach(11, 1, compute, proto::AttachMode::rw, rig.now).has_value());
    BOOST_TEST(rig.master.attach(11, 2, compute + 1, proto::AttachMode::rw, rig.now).has_value());
}

BOOST_AUTO_TEST_CASE(detach_retires_the_generation_until_fenced,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const auto gen = rig.master.attach(10, 0xA1, compute, proto::AttachMode::rw, rig.now);
    BOOST_REQUIRE(gen.has_value());
    BOOST_TEST(!rig.master.generation_fenced(10, *gen));
    rig.t.clear();
    BOOST_REQUIRE(rig.master.detach(10, 0xA1, rig.now).has_value());
    // The detached server still hears about it.
    BOOST_TEST(std::ranges::any_of(rig.t.configs, [](const proto::ReplicaConfig& c) {
        return c.server_id == compute && c.attachments.empty();
    }));
    BOOST_TEST(!rig.master.generation_fenced(10, *gen));  // not applied yet
    rig.status(rig.with_role(10, ReplicaRole::secondary).front(), 10);
    BOOST_TEST(!rig.master.generation_fenced(10, *gen));  // a secondary does not serve
    rig.status(rig.primary(10), 10);
    BOOST_TEST(rig.master.generation_fenced(10, *gen));
    // A new attachment takes a new generation.
    const auto again = rig.master.attach(10, 0xA2, compute + 1, proto::AttachMode::rw, rig.now);
    BOOST_TEST(*again == *gen + 1);
    BOOST_TEST(rig.master.detach(10, 0xA1, rig.now).error() == m::Error::unknown_attachment);
}

BOOST_AUTO_TEST_CASE(resends_configs_a_member_has_not_applied,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    rig.status(p, 10);
    rig.t.clear();
    rig.advance(Time{1000});
    // Only the member that has not reported epoch 1 gets it again.
    BOOST_REQUIRE(rig.t.configs.size() == 1U);
    BOOST_TEST(rig.t.configs[0].server_id != p);
    BOOST_TEST(rig.t.configs[0].epoch == 1U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(leases_and_failover)

BOOST_AUTO_TEST_CASE(grants_leases_to_the_current_primary_only,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    const std::uint64_t s = rig.with_role(10, ReplicaRole::secondary).front();
    rig.status(s, 10);
    BOOST_TEST(rig.t.leases.empty());
    rig.status(p, 10, 0, std::nullopt, 0);  // an older epoch
    BOOST_TEST(rig.t.leases.empty());
    rig.status(p, 10);
    BOOST_REQUIRE(rig.t.leases.size() == 1U);
    BOOST_TEST(std::get<0>(rig.t.leases[0]) == p);
    BOOST_TEST(std::get<2>(rig.t.leases[0]) == 1U);
}

BOOST_AUTO_TEST_CASE(a_lost_secondary_leaves_and_is_rebuilt,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    const std::uint64_t s = rig.with_role(10, ReplicaRole::secondary).front();
    rig.fault(p, 10, proto::VolumeFaultKind::member_timeout, s);
    BOOST_TEST(rig.vol(10).epoch == 2U);
    BOOST_TEST(rig.vol(10).members.size() == 1U);
    BOOST_REQUIRE(rig.vol(10).away.size() == 1U);
    BOOST_TEST(rig.vol(10).away[0].server_id == s);
    // Its server is still reporting, but the replica is out until resync
    // or rebuild: tick starts a rebuild on the third server.
    rig.advance(Time{100});
    const auto joining = rig.with_role(10, ReplicaRole::joining);
    BOOST_REQUIRE(joining.size() == 1U);
    BOOST_TEST(joining[0] != s);
    BOOST_TEST(joining[0] != p);
    BOOST_TEST(rig.vol(10).epoch == 3U);
    // Joined: a secondary at the next epoch.
    rig.status(joining[0], 10, 0, proto::ReplicaState::in_sync);
    BOOST_TEST(rig.with_role(10, ReplicaRole::secondary) == joining);
    BOOST_TEST(rig.vol(10).epoch == 4U);
    // A fault from a non-primary about a member is not believed.
    rig.fault(joining[0], 10, proto::VolumeFaultKind::member_timeout, p);
    BOOST_TEST(rig.primary(10) == p);
}

BOOST_AUTO_TEST_CASE(an_initiator_alone_cannot_depose_the_primary,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10, m::general_class());
    const std::uint64_t p = rig.primary(10);
    rig.status(p, 10);
    rig.fault(compute, 10, proto::VolumeFaultKind::primary_timeout, p,
              proto::FaultReporter::initiator);  // not a storage server: ignored
    rig.fault(p, 10, proto::VolumeFaultKind::primary_timeout, p, proto::FaultReporter::initiator);
    BOOST_TEST(!rig.vol(10).failover);
    rig.advance(Time{20'000});
    rig.advance(Time{100});
    BOOST_TEST(rig.primary(10) == p);
    BOOST_TEST(rig.vol(10).primary_suspects.empty());  // the suspicion expired
}

BOOST_AUTO_TEST_CASE(a_confirmed_primary_failure_waits_out_the_lease,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3, 4}};
    rig.create(10, m::provisioned_class());
    const std::uint64_t p = rig.primary(10);
    const auto secs = rig.with_role(10, ReplicaRole::secondary);
    rig.status(secs[0], 10, 5);
    rig.status(secs[1], 10, 7);  // the most up to date
    rig.status(p, 10, 7);
    const std::size_t granted = rig.t.leases.size();
    rig.fault(secs[0], 10, proto::VolumeFaultKind::primary_timeout, p);
    BOOST_TEST(rig.vol(10).failover);
    rig.status(p, 10, 7);  // asks again: no acknowledgement now
    BOOST_TEST(rig.t.leases.size() == granted);
    rig.advance(lease_wait() - Time{1});
    BOOST_TEST(rig.primary(10) == p);  // its lease may still run
    rig.advance(Time{1});
    BOOST_TEST(rig.primary(10) == secs[1]);
    BOOST_TEST(rig.vol(10).away.size() == 1U);
    BOOST_TEST(rig.vol(10).away[0].server_id == p);
    BOOST_TEST(!rig.vol(10).failover);
}

BOOST_AUTO_TEST_CASE(a_silent_server_loses_its_replicas,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    rig.status(p, 10);
    rig.advance(Time{10'001}, p);  // p silent past server_silence
    BOOST_TEST(!rig.master.server_up(p));
    // Its last lease ran out long ago: replaced in the same tick.
    BOOST_TEST(rig.primary(10) != p);
    BOOST_TEST(rig.primary(10) != 0U);
    BOOST_TEST(!rig.vol(10).failover);
}

BOOST_AUTO_TEST_CASE(no_in_sync_replica_suspends_until_enable_io,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    const std::uint64_t s = rig.with_role(10, ReplicaRole::secondary).front();
    rig.status(s, 10, 3);
    rig.fault(p, 10, proto::VolumeFaultKind::member_timeout, s);  // s out
    BOOST_TEST(rig.master.enable_io(10, rig.now).error() == m::Error::not_suspended);
    rig.advance(Time{10'001}, p);  // then p's server goes silent
    rig.advance(lease_wait(), p);
    const auto& v = rig.vol(10);
    BOOST_TEST((v.flags & proto::replica_flags::io_suspended) != 0U);
    BOOST_TEST((v.flags & proto::replica_flags::impaired) != 0U);
    BOOST_TEST(rig.primary(10) == p);  // still listed; nobody serves
    // No rebuild without a primary to copy from.
    rig.advance(Time{100}, p);
    BOOST_TEST(rig.with_role(10, ReplicaRole::joining).empty());
    // The operator resumes from the best reachable replica: s.
    BOOST_REQUIRE(rig.master.enable_io(10, rig.now).has_value());
    BOOST_TEST(rig.primary(10) == s);
    BOOST_TEST(rig.vol(10).loss_possible);
    BOOST_TEST((rig.vol(10).flags & proto::replica_flags::io_suspended) == 0U);
    BOOST_TEST(rig.t.ops_of<proto::DeleteReplica>().size() == 1U);  // p's copy
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(rebuild)

BOOST_AUTO_TEST_CASE(a_returning_replica_resyncs_in_place,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    const std::uint64_t s = rig.with_role(10, ReplicaRole::secondary).front();
    const std::uint32_t gen = rig.gen_of(10, s);
    rig.status(p, 10);
    rig.advance(Time{10'001}, s);  // s down
    BOOST_TEST(!rig.master.server_up(s));
    rig.advance(Time{100}, s);  // a replacement starts on the third server
    const auto replacement = rig.with_role(10, ReplicaRole::joining);
    BOOST_REQUIRE(replacement.size() == 1U);
    rig.t.clear();
    rig.heartbeat();  // s is back within the window
    BOOST_TEST(rig.master.server_up(s));
    const auto joining = rig.with_role(10, ReplicaRole::joining);
    BOOST_REQUIRE(joining.size() == 1U);
    BOOST_TEST(joining[0] == s);
    BOOST_TEST(rig.gen_of(10, s) == gen);  // same replica: partial resync
    const auto deletes = rig.t.ops_of<proto::DeleteReplica>();
    BOOST_REQUIRE(deletes.size() == 1U);
    BOOST_TEST(deletes[0].server_id == replacement[0]);
}

BOOST_AUTO_TEST_CASE(a_replica_back_after_the_window_is_deleted,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2}};  // no third server: nothing to rebuild on
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    const std::uint64_t s = rig.with_role(10, ReplicaRole::secondary).front();
    const std::uint32_t old_gen = rig.gen_of(10, s);
    rig.status(p, 10);
    rig.advance(Time{10'001}, s);
    for (int i = 0; i < 16; ++i) {
        rig.advance(Time{60'000}, s);  // past the 15-minute window
    }
    BOOST_TEST(rig.vol(10).away.empty());
    rig.t.clear();
    rig.heartbeat();  // s back
    // Its old replica was deleted at expiry; a fresh rebuild targets it.
    rig.advance(Time{100});
    BOOST_TEST(rig.with_role(10, ReplicaRole::joining) == std::vector<std::uint64_t>{s});
    BOOST_TEST(rig.gen_of(10, s) != old_gen);
}

BOOST_AUTO_TEST_CASE(a_reachable_replica_rejoins_after_a_pause,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2}};  // nowhere else to rebuild
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    const std::uint64_t s = rig.with_role(10, ReplicaRole::secondary).front();
    const std::uint32_t gen = rig.gen_of(10, s);
    rig.fault(p, 10, proto::VolumeFaultKind::member_timeout, s);
    rig.advance(Time{29'000});
    BOOST_TEST(rig.with_role(10, ReplicaRole::joining).empty());  // not yet: no flapping
    rig.advance(Time{1000});
    BOOST_TEST(rig.with_role(10, ReplicaRole::joining) == std::vector<std::uint64_t>{s});
    BOOST_TEST(rig.gen_of(10, s) == gen);
    BOOST_TEST(rig.vol(10).away.empty());
}

BOOST_AUTO_TEST_CASE(fewest_in_sync_rebuilds_first,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3, 4, 5}, {.rebuilds = 1, .rebuilds_per_server = 2, .drain_moves = 4}};
    rig.create(10, m::provisioned_class());
    rig.create(20, m::provisioned_class());
    // Volume 10 loses two secondaries, volume 20 one.
    const std::uint64_t p10 = rig.primary(10);
    for (const auto s : rig.with_role(10, ReplicaRole::secondary)) {
        rig.fault(p10, 10, proto::VolumeFaultKind::member_timeout, s);
    }
    const std::uint64_t p20 = rig.primary(20);
    rig.fault(p20, 20, proto::VolumeFaultKind::member_timeout,
              rig.with_role(20, ReplicaRole::secondary).front());
    rig.advance(Time{100});
    BOOST_TEST(rig.with_role(10, ReplicaRole::joining).size() == 1U);
    BOOST_TEST(rig.with_role(20, ReplicaRole::joining).empty());  // the limit
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(moves)

BOOST_AUTO_TEST_CASE(a_secondary_moves_without_dropping_the_count,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t s = rig.with_role(10, ReplicaRole::secondary).front();
    const std::uint64_t target = 6 - s - rig.primary(10);  // the server not in the set
    BOOST_REQUIRE(rig.master.move_replica(10, s, 0, rig.now).has_value());
    BOOST_TEST(rig.with_role(10, ReplicaRole::joining) == std::vector<std::uint64_t>{target});
    BOOST_TEST(rig.master.move_replica(10, s, 0, rig.now).error() == m::Error::busy);
    rig.t.clear();
    rig.status(target, 10, 0, proto::ReplicaState::in_sync);
    BOOST_TEST(rig.vol(10).members.size() == 2U);
    BOOST_TEST(rig.with_role(10, ReplicaRole::secondary) == std::vector<std::uint64_t>{target});
    // The target joined at one epoch and the source left at the next.
    BOOST_TEST(rig.vol(10).epoch == 4U);
    const auto deletes = rig.t.ops_of<proto::DeleteReplica>();
    BOOST_REQUIRE(deletes.size() == 1U);
    BOOST_TEST(deletes[0].server_id == s);
    BOOST_TEST(!rig.vol(10).move.has_value());
}

BOOST_AUTO_TEST_CASE(the_primary_hands_over_on_confirmed_demotion,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    rig.status(p, 10);
    const std::uint64_t target = 6 - p - rig.with_role(10, ReplicaRole::secondary).front();
    BOOST_REQUIRE(rig.master.move_replica(10, p, target, rig.now).has_value());
    rig.status(target, 10, 0, proto::ReplicaState::in_sync);
    // Leaving: no primary at this epoch, I/O waits, no lease.
    BOOST_TEST(rig.with_role(10, ReplicaRole::leaving) == std::vector<std::uint64_t>{p});
    BOOST_TEST((rig.vol(10).flags & proto::replica_flags::io_suspended) != 0U);
    const std::size_t granted = rig.t.leases.size();
    rig.status(p, 10);
    BOOST_TEST(rig.t.leases.size() == granted);
    rig.report(p, proto::DemotionConfirmed{.volume_id = 10, .epoch = rig.vol(10).epoch});
    // At once, without waiting for the lease.
    BOOST_TEST(rig.primary(10) == target);
    BOOST_TEST((rig.vol(10).flags & proto::replica_flags::io_suspended) == 0U);
    BOOST_TEST(rig.vol(10).members.size() == 2U);
    BOOST_TEST(rig.t.ops_of<proto::DeleteReplica>().back().server_id == p);
}

BOOST_AUTO_TEST_CASE(a_silent_handover_waits_for_the_lease,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    const std::uint64_t p = rig.primary(10);
    rig.status(p, 10);
    BOOST_REQUIRE(rig.master.move_replica(10, p, 0, rig.now).has_value());
    const std::uint64_t target = rig.with_role(10, ReplicaRole::joining).front();
    rig.status(target, 10, 0, proto::ReplicaState::in_sync);
    rig.advance(lease_wait() - Time{1});
    BOOST_TEST(rig.primary(10) == 0U);
    rig.advance(Time{1});
    BOOST_TEST(rig.primary(10) == target);
}

BOOST_AUTO_TEST_CASE(drain_empties_a_server, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3, 4}};
    rig.create(10);
    rig.create(20);
    const std::uint64_t victim = rig.primary(10);
    BOOST_REQUIRE(rig.master.drain(victim).has_value());
    BOOST_TEST(!rig.master.drained(victim));
    for (int round = 0; round < 8 && !rig.master.drained(victim); ++round) {
        rig.advance(Time{100});
        for (const std::uint64_t id : {10U, 20U}) {
            for (const auto j : rig.with_role(id, ReplicaRole::joining)) {
                rig.status(j, id, 0, proto::ReplicaState::in_sync);
            }
            if (!rig.with_role(id, ReplicaRole::leaving).empty()) {
                rig.report(victim,
                           proto::DemotionConfirmed{.volume_id = id, .epoch = rig.vol(id).epoch});
            }
        }
        for (const auto& op : std::vector(rig.t.ops)) {
            rig.outcome(op);  // replicas confirm deletes
        }
        rig.t.ops.clear();
    }
    BOOST_TEST(rig.master.drained(victim));
    for (const std::uint64_t id : {10U, 20U}) {
        BOOST_TEST(rig.vol(id).members.size() == 2U);
        BOOST_TEST(rig.primary(id) != 0U);
    }
    // Nothing new lands on it.
    rig.create(30);
    BOOST_TEST(rig.gen_of(30, victim) == 0U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(snapshots)

BOOST_AUTO_TEST_CASE(a_multi_volume_cut_prepares_commits_and_uploads,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    rig.create(20);
    const std::vector<std::uint64_t> vols{10, 20};
    BOOST_REQUIRE(rig.master.create_snapshot(0x5A, vols, 3, rig.now).has_value());
    BOOST_TEST(rig.master.create_snapshot(0x5B, vols, 3, rig.now).error() == m::Error::busy);
    const auto prepares = rig.t.ops_of<proto::SnapshotPrepare>();
    BOOST_REQUIRE(prepares.size() == 2U);
    BOOST_TEST(prepares[0].server_id == rig.primary(10));
    rig.outcome(prepares[0], proto::OpStatus::ok, 41);
    BOOST_TEST(rig.t.ops_of<proto::SnapshotCommit>().empty());  // waits for all
    rig.outcome(prepares[1], proto::OpStatus::ok, 42);
    const auto commits = rig.t.ops_of<proto::SnapshotCommit>();
    BOOST_TEST(commits.size() == 4U);  // every in-sync member of both
    const auto uploads = rig.t.ops_of<proto::SnapshotUpload>();
    BOOST_REQUIRE(uploads.size() == 2U);
    // A secondary uploads; the first snapshot has no parent.
    BOOST_TEST(uploads[0].server_id == rig.with_role(10, ReplicaRole::secondary).front());
    BOOST_TEST((std::get<proto::SnapshotUpload>(uploads[0].args).parent_manifest ==
                proto::ManifestName{}));
    BOOST_TEST(rig.master.snapshot(0x5A)->status == m::SnapshotStatus::uploading);
    BOOST_TEST(rig.master.snapshot(0x5A)->parts[0].cut_seq == 41U);
    for (std::size_t i = 0; i < 2; ++i) {
        rig.report(
            uploads[i].server_id,
            proto::SnapshotProgress{.volume_id = uploads[i].volume_id,
                                    .cut_id = 0x5A,
                                    .state = proto::SnapshotState::completed,
                                    .manifest_name = manifest(static_cast<std::uint8_t>(i + 1))});
    }
    BOOST_TEST(rig.master.snapshot(0x5A)->status == m::SnapshotStatus::completed);
    // The next snapshot of volume 10 diffs against the first.
    rig.t.clear();
    BOOST_REQUIRE(
        rig.master.create_snapshot(0x5C, std::vector<std::uint64_t>{10}, 3, rig.now).has_value());
    rig.outcome(rig.t.ops_of<proto::SnapshotPrepare>()[0]);
    BOOST_TEST((std::get<proto::SnapshotUpload>(rig.t.ops_of<proto::SnapshotUpload>()[0].args)
                    .parent_manifest == manifest(1)));
}

BOOST_AUTO_TEST_CASE(a_refusal_or_a_timeout_aborts_the_cut,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    rig.create(20);
    const std::vector<std::uint64_t> vols{10, 20};
    BOOST_REQUIRE(rig.master.create_snapshot(1, vols, 3, rig.now).has_value());
    rig.outcome(rig.t.ops_of<proto::SnapshotPrepare>()[0], proto::OpStatus::timed_out);
    BOOST_TEST(rig.master.snapshot(1)->status == m::SnapshotStatus::failed);
    BOOST_TEST(rig.t.ops_of<proto::SnapshotAbort>().size() == 2U);
    rig.t.clear();
    BOOST_REQUIRE(rig.master.create_snapshot(2, vols, 3, rig.now).has_value());
    rig.advance(Time{1000});  // prepare_timeout_ms
    BOOST_TEST(rig.master.snapshot(2)->status == m::SnapshotStatus::failed);
    const auto aborts = rig.t.ops_of<proto::SnapshotAbort>();
    BOOST_TEST(std::ranges::count_if(aborts, [](const proto::VolumeOp& o) {
                   return std::get<proto::SnapshotAbort>(o.args).cut_id == 2;
               }) == 2);
    BOOST_TEST(rig.t.ops_of<proto::SnapshotCommit>().empty());
}

BOOST_AUTO_TEST_CASE(losing_the_uploader_fails_the_snapshot,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    BOOST_REQUIRE(
        rig.master.create_snapshot(1, std::vector<std::uint64_t>{10}, 3, rig.now).has_value());
    rig.outcome(rig.t.ops_of<proto::SnapshotPrepare>()[0]);
    const auto up = rig.t.ops_of<proto::SnapshotUpload>();
    BOOST_REQUIRE(up.size() == 1U);
    rig.fault(rig.primary(10), 10, proto::VolumeFaultKind::member_timeout, up[0].server_id);
    BOOST_TEST(rig.master.snapshot(1)->status == m::SnapshotStatus::failed);
    BOOST_TEST(rig.t.sweeps.size() == 1U);  // what it uploaded is swept
    // A new snapshot may start.
    BOOST_TEST(
        rig.master.create_snapshot(2, std::vector<std::uint64_t>{10}, 3, rig.now).has_value());
}

BOOST_AUTO_TEST_CASE(gc_sweeps_one_lineage_at_a_time_and_uploads_wait,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    auto snap = [&](std::uint64_t id, std::uint8_t name) {
        rig.t.clear();
        BOOST_REQUIRE(
            rig.master.create_snapshot(id, std::vector<std::uint64_t>{10}, 3, rig.now).has_value());
        rig.outcome(rig.t.ops_of<proto::SnapshotPrepare>()[0]);
        const auto up = rig.t.ops_of<proto::SnapshotUpload>();
        if (!up.empty() && name != 0) {
            rig.report(up[0].server_id,
                       proto::SnapshotProgress{.volume_id = 10,
                                               .cut_id = id,
                                               .state = proto::SnapshotState::completed,
                                               .manifest_name = manifest(name)});
        }
    };
    snap(1, 1);
    rig.advance(Time{10});
    snap(2, 2);
    BOOST_REQUIRE(rig.master.delete_snapshot(1, rig.now).has_value());
    BOOST_REQUIRE(rig.t.sweeps.size() == 1U);
    BOOST_TEST(rig.t.sweeps[0].first == 10U);
    BOOST_TEST((rig.t.sweeps[0].second == std::vector<proto::ManifestName>{manifest(2)}));
    // While it sweeps, a new snapshot cuts but does not upload.
    snap(3, 0);
    BOOST_TEST(rig.t.ops_of<proto::SnapshotUpload>().empty());
    rig.master.gc_finished(10, rig.now);
    const auto up = rig.t.ops_of<proto::SnapshotUpload>();
    BOOST_REQUIRE(up.size() == 1U);
    BOOST_TEST((std::get<proto::SnapshotUpload>(up[0].args).parent_manifest == manifest(2)));
    // Deleting the parent while snapshot 3 uploads: the sweep waits for it.
    BOOST_REQUIRE(rig.master.delete_snapshot(2, rig.now).has_value());
    BOOST_TEST(rig.t.sweeps.size() == 1U);
    rig.report(up[0].server_id, proto::SnapshotProgress{.volume_id = 10,
                                                        .cut_id = 3,
                                                        .state = proto::SnapshotState::completed,
                                                        .manifest_name = manifest(3)});
    BOOST_REQUIRE(rig.t.sweeps.size() == 2U);
    BOOST_TEST((rig.t.sweeps[1].second == std::vector<proto::ManifestName>{manifest(3)}));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(erasure_and_ops)

BOOST_AUTO_TEST_CASE(the_last_volume_destroys_the_lineage_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    rig.create(11, m::general_class(), 10);  // same lineage (a restore)
    BOOST_REQUIRE(rig.master.delete_volume(10, rig.now).has_value());
    BOOST_TEST(rig.t.destroyed.empty());
    BOOST_TEST(rig.t.ops_of<proto::DeleteReplica>().size() == 2U);
    // A snapshot keeps the lineage alive past its last volume.
    BOOST_REQUIRE(
        rig.master.create_snapshot(7, std::vector<std::uint64_t>{11}, 3, rig.now).has_value());
    rig.outcome(rig.t.ops_of<proto::SnapshotPrepare>()[0]);
    const auto up = rig.t.ops_of<proto::SnapshotUpload>()[0];
    rig.report(up.server_id, proto::SnapshotProgress{.volume_id = 11,
                                                     .cut_id = 7,
                                                     .state = proto::SnapshotState::completed,
                                                     .manifest_name = manifest(7)});
    BOOST_REQUIRE(rig.master.delete_volume(11, rig.now).has_value());
    BOOST_TEST(rig.t.destroyed.empty());
    BOOST_REQUIRE(rig.master.delete_snapshot(7, rig.now).has_value());
    BOOST_TEST(rig.t.destroyed.empty());  // the sweep first
    BOOST_REQUIRE(rig.t.sweeps.size() == 1U);
    BOOST_TEST(rig.t.sweeps[0].second.empty());
    rig.master.gc_finished(10, rig.now);
    BOOST_TEST(rig.t.destroyed == std::vector<std::uint64_t>{10});
    BOOST_TEST(rig.master.lineage_erased(10));
    auto again = rig.master.create_volume(
        {.volume_id = 12, .lineage_id = 10, .capacity_blocks = blocks_1g}, rig.now);
    BOOST_TEST(again.error() == m::Error::erased_lineage);
}

BOOST_AUTO_TEST_CASE(ops_are_resent_until_their_outcome,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    BOOST_REQUIRE(rig.master.delete_volume(10, rig.now).has_value());
    BOOST_TEST(rig.master.pending_ops() == 2U);
    const auto first = rig.t.ops;
    rig.t.clear();
    rig.advance(Time{1000});
    BOOST_REQUIRE(rig.t.ops.size() == 2U);
    BOOST_TEST(rig.t.ops[0].op_id == first[0].op_id);  // the same op: run once
    rig.outcome(first[0]);
    rig.outcome(first[0]);  // a duplicate outcome is harmless
    rig.outcome(first[1]);
    BOOST_TEST(rig.master.pending_ops() == 0U);
    rig.t.clear();
    rig.advance(Time{1000});
    BOOST_TEST(rig.t.ops.empty());
}

BOOST_AUTO_TEST_CASE(stale_epoch_faults_resend_the_config,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{{1, 2, 3}};
    rig.create(10);
    BOOST_REQUIRE(rig.master.attach(10, 1, compute, proto::AttachMode::rw, rig.now).has_value());
    const std::uint64_t p = rig.primary(10);
    rig.t.clear();
    rig.fault(p, 10, proto::VolumeFaultKind::stale_epoch, compute);
    BOOST_REQUIRE(rig.t.configs.size() == 1U);
    BOOST_TEST(rig.t.configs[0].server_id == compute);
    BOOST_TEST(rig.t.configs[0].epoch == rig.vol(10).epoch);
    rig.t.clear();
    rig.fault(p, 10, proto::VolumeFaultKind::stale_epoch, 0xBAD);  // a stranger
    BOOST_TEST(rig.t.configs.empty());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(properties)

// Random interleavings of faults, silences, returns, joins, moves,
// attachments and snapshots. The recorder checks every config against the
// decoder and per-recipient epoch order; here: at most one primary, one
// unless suspended, members in distinct racks and never more than five.
BOOST_AUTO_TEST_CASE(random_events_keep_the_invariants,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr int seeds = 20;
    constexpr int steps = 400;
    for (int seed = 1; seed <= seeds; ++seed) {
        Rig rig{{1, 2, 3, 4, 5, 6}};
        std::minstd_rand rng{static_cast<std::minstd_rand::result_type>(seed)};
        auto pick = [&](std::size_t n) { return static_cast<std::size_t>(rng() % n); };
        const std::vector<std::uint64_t> vols{10, 20, 30};
        rig.create(10, m::provisioned_class());
        rig.create(20);
        rig.create(30);
        std::set<std::uint64_t> silent;
        std::uint64_t next_id = 100;
        for (int step = 0; step < steps; ++step) {
            const std::uint64_t id = vols[pick(vols.size())];
            const auto& v = rig.vol(id);
            const std::uint64_t any =
                v.members.empty() ? 1 : v.members[pick(v.members.size())].server_id;
            switch (pick(10)) {
                case 0:
                    if (rig.primary(id) != 0) {
                        rig.fault(rig.primary(id), id, proto::VolumeFaultKind::member_timeout, any);
                    }
                    break;
                case 1:
                    rig.fault(any, id, proto::VolumeFaultKind::primary_timeout, rig.primary(id));
                    break;
                case 2:
                    if (silent.size() < 2) {
                        silent.insert(1 + pick(6));
                    }
                    break;
                case 3:
                    silent.clear();
                    break;
                case 4:
                    for (const auto j : rig.with_role(id, ReplicaRole::joining)) {
                        if (!silent.contains(j)) {
                            rig.status(j, id, 0, proto::ReplicaState::in_sync);
                        }
                    }
                    break;
                case 5:
                    static_cast<void>(rig.master.move_replica(id, any, 0, rig.now));
                    break;
                case 6:
                    for (const auto l : rig.with_role(id, ReplicaRole::leaving)) {
                        rig.report(l, proto::DemotionConfirmed{.volume_id = id,
                                                               .epoch = rig.vol(id).epoch});
                    }
                    break;
                case 7:
                    if (v.attachments.empty()) {
                        static_cast<void>(rig.master.attach(id, next_id++, compute,
                                                            proto::AttachMode::rw, rig.now));
                    } else {
                        static_cast<void>(
                            rig.master.detach(id, v.attachments.front().attachment_id, rig.now));
                    }
                    break;
                case 8:
                    static_cast<void>(rig.master.create_snapshot(
                        next_id++, std::vector<std::uint64_t>{id}, 3, rig.now));
                    for (const auto& op : std::vector(rig.t.ops)) {
                        rig.outcome(op);
                    }
                    rig.t.ops.clear();
                    break;
                default:
                    break;
            }
            // Time passes; members not silenced report status.
            rig.now += Time{static_cast<Time::rep>(200 + pick(3000))};
            for (std::uint64_t srv = 1; srv <= 6; ++srv) {
                if (silent.contains(srv)) {
                    continue;
                }
                rig.report(srv, proto::ReplicaStatus{});
                for (const std::uint64_t vid : vols) {
                    for (const auto& mem : rig.vol(vid).members) {
                        if (mem.server_id == srv && mem.role != ReplicaRole::joining) {
                            rig.status(srv, vid, static_cast<std::uint64_t>(step));
                            break;
                        }
                    }
                }
            }
            rig.master.tick(rig.now);
            for (const std::uint64_t vid : vols) {
                const auto& vv = rig.vol(vid);
                const auto primaries = rig.with_role(vid, ReplicaRole::primary).size();
                const bool susp = (vv.flags & proto::replica_flags::io_suspended) != 0;
                BOOST_TEST_REQUIRE(primaries <= 1U, "seed " << seed << " step " << step);
                BOOST_TEST_REQUIRE((susp || primaries == 1U), "seed " << seed << " step " << step);
                BOOST_TEST_REQUIRE(vv.members.size() <= proto::max_replica_members);
                std::set<std::uint64_t> seen;  // one rack per server here
                for (const auto& mem : vv.members) {
                    BOOST_TEST_REQUIRE(seen.insert(mem.server_id).second,
                                       "seed " << seed << " step " << step);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
