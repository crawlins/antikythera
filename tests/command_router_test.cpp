// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirements 1.5, 2.3, 3, 4, 9: the
// CommandRouter's sequencing, compensation, timeouts, cleaning and status.

#define BOOST_TEST_MODULE command_router_test
#include <boost/test/unit_test.hpp>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "helm/audit_log.hpp"
#include "helm/command_router.hpp"
#include "helm/device_pool.hpp"
#include "helm/key_store.hpp"
#include "helm/mailbox.hpp"
#include "helm/secure_element.hpp"
#include "proto/envelope.hpp"
#include "proto/report.hpp"
#include "test_support.hpp"

namespace ak::helm {
// Reads a delivered key (image volumes get a fresh one per attachment).
struct ScopedKeyTestAccess {
    static auto bytes(const ScopedKey& k) -> std::vector<std::byte> {
        const auto b = k.bytes();
        return {b.begin(), b.end()};
    }
};
}  // namespace ak::helm

namespace helm = ak::helm;
namespace mb = ak::helm::mailbox;
namespace oar = ak::helm::oar;
namespace proto = ak::proto;

using ak::test::unit_timeout_seconds;
using helm::FunctionId;
using helm::FunctionState;
using helm::FunctionType;
using helm::LinkErrc;
using helm::LinkError;
using helm::VmId;
using helm::VolumeId;

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::uint64_t server = 1;
constexpr mb::KeyId key_id = 1;
constexpr VmId vm_one = 101;
constexpr VmId vm_two = 102;
constexpr VolumeId vol_one = 201;
constexpr VolumeId vol_two = 202;
constexpr std::uint8_t blk_slot = 2;
constexpr std::uint8_t net_slot = 3;
constexpr std::uint8_t gpu_slot = 4;
constexpr std::uint8_t second_blk_slot = 5;
constexpr std::uint64_t sectors_per_gib = std::uint64_t{1} << 21U;
constexpr std::uint16_t fn_zero = 0;
constexpr std::uint16_t fn_one = 1;
constexpr std::uint16_t vcpus = 4;
constexpr std::uint32_t memory_mib = 4096;
constexpr std::uint32_t size_gib = 20;
constexpr std::uint32_t vni = 0x1234;
constexpr std::uint64_t nic_id = 0xA1;
constexpr std::uint16_t detach_timeout_s = 5;
constexpr std::size_t small_queue = 2;
constexpr auto command_timeout = std::chrono::seconds{30};
constexpr auto release_timeout = std::chrono::seconds{60};
constexpr auto clean_timeout = std::chrono::seconds{90};
constexpr std::uint8_t sig_fill = 0x5A;

// ---- fakes -----------------------------------------------------------------

struct FakeHost final : helm::HostPort {
    std::vector<mb::Slot> posted;
    bool fail{false};
    auto post_command(const mb::Slot& slot) -> bool override {
        if (fail) {
            return false;
        }
        posted.push_back(slot);
        return true;
    }
};

struct FakeOar final : helm::OarPort {
    std::vector<oar::PrepareFunction> prepared;
    std::vector<oar::CleanFunction> cleaned;
    std::vector<std::pair<oar::FunctionNumber, VolumeId>> keys;
    std::vector<oar::DropKey> dropped;
    struct Stored {
        VolumeId volume{0};
        VmId owner{0};
        std::uint64_t capacity_sectors{0};
        std::uint32_t block_size{0};
        std::vector<std::byte> wrapped_key;
        std::uint16_t image_store{0};
        oar::ImageName image_name{};
    };
    std::vector<Stored> created;
    std::vector<std::vector<std::byte>> key_bytes;  // every key delivered, in order
    std::vector<VolumeId> deleted;
    std::vector<Stored> rewrapped;
    std::optional<LinkError> prepare_error;
    std::optional<LinkError> clean_error;
    std::optional<LinkError> deliver_error;
    std::optional<LinkError> create_error;
    std::optional<LinkError> delete_error;
    std::optional<LinkError> rewrap_error;

    auto prepare_function(const oar::PrepareFunction& r)
        -> std::expected<void, LinkError> override {
        prepared.push_back(r);
        if (prepare_error) {
            return std::unexpected(*prepare_error);
        }
        return {};
    }
    auto clean_function(const oar::CleanFunction& r) -> std::expected<void, LinkError> override {
        cleaned.push_back(r);
        if (clean_error) {
            return std::unexpected(*clean_error);
        }
        return {};
    }
    auto deliver_key(oar::FunctionNumber fn, VolumeId volume, helm::ScopedKey key)
        -> std::expected<void, LinkError> override {
        keys.emplace_back(fn, volume);
        key_bytes.push_back(helm::ScopedKeyTestAccess::bytes(key));
        if (deliver_error) {
            return std::unexpected(*deliver_error);
        }
        return {};
    }
    auto drop_key(const oar::DropKey& r) -> std::expected<void, LinkError> override {
        dropped.push_back(r);
        return {};
    }
    auto create_volume(const oar::CreateVolume& r) -> std::expected<void, LinkError> override {
        created.push_back({.volume = r.volume_id,
                           .owner = r.owner_vm,
                           .capacity_sectors = r.capacity_sectors,
                           .block_size = r.block_size,
                           .wrapped_key = {r.wrapped_key.begin(), r.wrapped_key.end()},
                           .image_store = r.image_store,
                           .image_name = r.image_name});
        if (create_error) {
            return std::unexpected(*create_error);
        }
        return {};
    }
    auto delete_volume(const oar::DeleteVolume& r) -> std::expected<void, LinkError> override {
        deleted.push_back(r.volume_id);
        if (delete_error) {
            return std::unexpected(*delete_error);
        }
        return {};
    }
    auto rewrap_volume(const oar::RewrapVolume& r) -> std::expected<void, LinkError> override {
        rewrapped.push_back({.volume = r.volume_id,
                             .owner = r.owner_vm,
                             .capacity_sectors = 0,
                             .block_size = 0,
                             .wrapped_key = {r.wrapped_key.begin(), r.wrapped_key.end()},
                             .image_store = 0,
                             .image_name = {}});
        if (rewrap_error) {
            return std::unexpected(*rewrap_error);
        }
        return {};
    }
};

struct FakeReports final : helm::ReportSink {
    std::vector<proto::ReportBody> all;
    auto report(proto::ReportBody body) -> void override { all.push_back(std::move(body)); }

    [[nodiscard]] auto outcomes() const -> std::vector<proto::CommandOutcome> {
        std::vector<proto::CommandOutcome> out;
        for (const auto& b : all) {
            if (const auto* o = std::get_if<proto::CommandOutcome>(&b)) {
                out.push_back(*o);
            }
        }
        return out;
    }
    [[nodiscard]] auto last_outcome() const -> proto::CommandOutcome {
        auto o = outcomes();
        BOOST_REQUIRE(!o.empty());
        return o.back();
    }
    [[nodiscard]] auto pool_changes() const -> std::vector<proto::PoolStateChange> {
        std::vector<proto::PoolStateChange> out;
        for (const auto& b : all) {
            if (const auto* p = std::get_if<proto::PoolStateChange>(&b)) {
                out.push_back(*p);
            }
        }
        return out;
    }
};

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-router-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() { std::filesystem::remove_all(path); }
};

auto make_se() -> helm::SoftwareSecureElement {
    auto se = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se);
    return std::move(*se);
}

auto make_audit(const TempDir& dir) -> helm::AuditLog {
    auto log = helm::AuditLog::open((dir.path / "audit.log").string(),
                                    {.sync = false, .clock = [] { return std::int64_t{0}; }});
    BOOST_REQUIRE(log);
    return std::move(*log);
}

// ---- wire helpers ----------------------------------------------------------

auto command_slot(std::uint64_t seq, const mb::Body& body) -> mb::Slot {
    const auto bytes = mb::encode_body(body);
    std::array<std::byte, mb::signature_size> sig{};
    sig.fill(std::byte{sig_fill});
    auto slot = mb::encode({.type = mb::type_of(body),
                            .seq = seq,
                            .body_len = static_cast<std::uint16_t>(bytes.size()),
                            .key_id = key_id,
                            .server_id = server},
                           bytes, sig);
    BOOST_REQUIRE(slot);
    return *slot;
}

auto envelope(std::uint64_t seq, const mb::Body& body) -> proto::Envelope {
    proto::Envelope env{.server_id = server, .key_id = key_id, .slot = {}};
    const auto slot = command_slot(seq, body);
    std::ranges::copy(slot, env.slot.begin());
    return env;
}

auto host_slot(const mb::Body& body) -> mb::Slot {
    const auto bytes = mb::encode_body(body);
    const std::array<std::byte, mb::signature_size> sig{};
    auto slot = mb::encode({.type = mb::type_of(body),
                            .seq = 0,
                            .body_len = static_cast<std::uint16_t>(bytes.size()),
                            .key_id = mb::no_key_id},
                           bytes, sig);
    BOOST_REQUIRE(slot);
    return *slot;
}

auto response(std::uint64_t seq, mb::Type command, mb::Status status) -> mb::Slot {
    return host_slot(mb::Response{.in_reply_to = seq, .command = command, .status = status});
}

auto blk(std::uint16_t fn) -> mb::DeviceRef {
    return {.slot = blk_slot, .type = mb::DeviceType::blk_fn, .function = fn};
}
auto nic(std::uint16_t fn) -> mb::DeviceRef {
    return {.slot = net_slot, .type = mb::DeviceType::nic_vf, .function = fn};
}
auto gpu(std::uint16_t fn) -> mb::DeviceRef {
    return {.slot = gpu_slot, .type = mb::DeviceType::gpu_whole, .function = fn};
}

auto inventory(oar::Role role, FunctionType type) -> oar::Inventory {
    oar::Inventory inv{.role = role, .vtep = {}, .functions = {}};
    inv.functions.push_back({.fn = fn_zero, .type = type});
    inv.functions.push_back({.fn = fn_one, .type = type});
    return inv;
}

auto test_nic_config() -> oar::NicConfig {
    oar::NicConfig c{.nic_id = nic_id, .vni = vni, .mac = {}};
    c.mac[0] = std::byte{0x02};
    return c;
}

// A NIC attach naming the VPC, NIC ID and MAC of test_nic_config().
auto nic_attach(VmId vm, std::uint16_t fn) -> mb::AttachDevice {
    const auto c = test_nic_config();
    return {.vm_id = vm, .device = nic(fn), .vni = c.vni, .nic_id = c.nic_id, .mac = c.mac};
}

// One helm, wired to fakes, with a blk, a net and a GPU slot registered
// and their functions cleaned (free).
struct Helm {
    TempDir dir;
    helm::SoftwareSecureElement se = make_se();
    helm::KeyStore keys{se};
    helm::DevicePool pool;
    helm::AuditLog audit = make_audit(dir);
    FakeHost host;
    FakeReports reports;
    FakeOar blk_role;
    FakeOar net_role;
    FakeOar gpu_role;
    Clock::time_point t{};
    std::uint64_t seq{0};
    helm::CommandRouter router;

    explicit Helm(std::size_t max_queued = helm::RouterConfig{}.max_queued, bool with_blk = true)
        : router{helm::RouterConfig{.last_seq = 0,
                                    .command_timeout = command_timeout,
                                    .release_timeout = release_timeout,
                                    .clean_timeout = clean_timeout,
                                    .max_queued = max_queued,
                                    .outcome_history = helm::RouterConfig{}.outcome_history,
                                    .clock = [this] { return t; }},
                 pool,
                 keys,
                 host,
                 reports,
                 audit} {
        if (with_blk) {
            router.add_slot(blk_slot, blk_role, inventory(oar::Role::blk, FunctionType::blk_fn));
        }
        router.add_slot(net_slot, net_role, inventory(oar::Role::net, FunctionType::nic_vf));
        router.add_slot(gpu_slot, gpu_role, inventory(oar::Role::gpu, FunctionType::gpu_whole));
        for (const auto fn : {fn_zero, fn_one}) {
            router.on_host_slot(
                host_slot(mb::ScrubDone{.device = gpu(fn), .result = mb::ScrubResult::ok}));
        }
        BOOST_REQUIRE(pool.first_free(FunctionType::gpu_whole));
        BOOST_REQUIRE(!with_blk || pool.first_free(FunctionType::blk_fn));
        BOOST_REQUIRE(pool.first_free(FunctionType::nic_vf));
        reports.all.clear();
        blk_role.cleaned.clear();
        net_role.cleaned.clear();
    }

    // Sends a command with the next sequence number; returns that number.
    auto send(const mb::Body& body) -> std::uint64_t {
        router.on_envelope(envelope(++seq, body));
        return seq;
    }
    auto answer(std::uint64_t s, const mb::Body& body, mb::Status status = mb::Status::ok) -> void {
        router.on_host_slot(response(s, mb::type_of(body), status));
    }
    // Sends and answers ok.
    auto run(const mb::Body& body, mb::Status status = mb::Status::ok) -> std::uint64_t {
        const auto s = send(body);
        answer(s, body, status);
        return s;
    }
    [[nodiscard]] auto state(std::uint8_t slot, std::uint16_t fn) const -> FunctionState {
        return pool.find(helm::make_function_id(slot, fn))->state;
    }
    [[nodiscard]] auto host_faults() const -> std::vector<proto::HostFaultReport> {
        std::vector<proto::HostFaultReport> out;
        for (const auto& b : reports.all) {
            if (const auto* f = std::get_if<proto::HostFaultReport>(&b)) {
                out.push_back(*f);
            }
        }
        return out;
    }
    [[nodiscard]] auto audit_text() const -> std::string {
        std::ifstream in{dir.path / "audit.log"};
        return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    }
};

auto status_of(const proto::CommandOutcome& o) -> mb::Status {
    return static_cast<mb::Status>(o.status);
}

}  // namespace

BOOST_AUTO_TEST_CASE(slots_are_relayed_unmodified_and_committed_on_ok,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    const mb::CreateVm create{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib};
    const auto s = h.send(create);
    BOOST_REQUIRE(h.host.posted.size() == 1U);
    BOOST_TEST((h.host.posted.at(0) == command_slot(s, create)));
    BOOST_TEST(h.router.busy());
    BOOST_TEST(h.keys.find_vm_key(vm_one).has_value());
    BOOST_TEST(h.router.inventory().vms.empty());  // not committed yet

    h.answer(s, create);
    BOOST_TEST(!h.router.busy());
    const auto o = h.reports.last_outcome();
    BOOST_TEST(o.in_reply_to == s);
    BOOST_TEST(o.command == static_cast<std::uint16_t>(mb::Type::create_vm));
    BOOST_TEST((status_of(o) == mb::Status::ok));
    const auto inv = h.router.inventory();
    BOOST_REQUIRE(inv.vms.size() == 1U);
    BOOST_TEST(inv.vms.at(0).vm_id == vm_one);
    BOOST_TEST(inv.vms.at(0).memory_mib == memory_mib);
    BOOST_TEST(inv.last_command_seq == s);

    const auto text = h.audit_text();
    BOOST_TEST(text.find("ev=command_received seq=1 cmd=0x1") != std::string::npos);
    BOOST_TEST(text.find("ev=vm_key_created seq=1 vm=101") != std::string::npos);
    BOOST_TEST(text.find("ev=command_relayed seq=1 cmd=0x1") != std::string::npos);
    BOOST_TEST(text.find("ev=command_outcome seq=1 cmd=0x1 status=0") != std::string::npos);
    BOOST_TEST(helm::verify_audit_log(text).has_value());
}

BOOST_AUTO_TEST_CASE(one_command_at_a_time_in_the_mailbox,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    const mb::CreateNetwork a{.vni = vni};
    const mb::CreateNetwork b{.vni = vni + 1};
    const auto first = h.send(a);
    const auto second = h.send(b);
    BOOST_TEST(h.host.posted.size() == 1U);
    BOOST_TEST(h.router.queued() == 1U);

    // A response to the queued command (not in flight) is ignored.
    h.answer(second, b);
    BOOST_TEST(h.host.posted.size() == 1U);
    BOOST_TEST(h.router.stats().stray_messages == 1U);

    h.answer(first, a);
    BOOST_REQUIRE(h.host.posted.size() == 2U);
    BOOST_TEST((h.host.posted.at(1) == command_slot(second, b)));
    h.answer(second, b);
    BOOST_TEST(h.router.inventory().networks.size() == 2U);
}

BOOST_AUTO_TEST_CASE(stale_sequences_are_dropped_and_retries_are_idempotent,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    const mb::CreateVm create{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib};
    const auto s = h.run(create);
    const auto reports_before = h.reports.outcomes().size();

    // The same envelope again: the recorded outcome, no second relay or key.
    h.router.on_envelope(envelope(s, create));
    BOOST_TEST(h.host.posted.size() == 1U);
    BOOST_TEST(h.reports.outcomes().size() == reports_before + 1);
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
    BOOST_TEST(h.router.stats().duplicates == 1U);

    // A retry of the command in flight is ignored.
    const mb::CreateNetwork net{.vni = vni};
    const auto n = h.send(net);
    h.router.on_envelope(envelope(n, net));
    BOOST_TEST(h.host.posted.size() == 2U);
    BOOST_TEST(h.router.stats().duplicates == 2U);
    h.answer(n, net);

    // Below the floor and never seen (0 is never a valid sequence number).
    h.router.on_envelope(envelope(0, net));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::stale_sequence));
    BOOST_TEST(h.host.posted.size() == 2U);
}

BOOST_AUTO_TEST_CASE(the_queue_is_bounded, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h{small_queue};
    const mb::ListVms list{};
    h.send(list);  // in flight
    h.send(list);
    h.send(list);  // queue full now
    const auto refused = h.send(list);
    const auto o = h.reports.last_outcome();
    BOOST_TEST(o.in_reply_to == refused);
    BOOST_TEST((status_of(o) == mb::Status::insufficient_resources));
    // Not accepted, so the controller may resend it once there is room.
    h.answer(1, list);
    h.router.on_envelope(envelope(refused, list));
    BOOST_TEST(h.router.queued() == small_queue);
}

BOOST_AUTO_TEST_CASE(malformed_and_reserved_commands_are_not_relayed,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    auto env = envelope(1, mb::ListVms{});
    env.slot.at(mb::header_reserved_offset) = std::byte{1};
    h.router.on_envelope(env);
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::malformed));

    // GPU_VF_CONFIG is reserved in the protocol: no body yet.
    auto gpu_cfg = envelope(2, mb::ListVms{});
    gpu_cfg.slot.at(0x06) = std::byte{0x40};
    h.router.on_envelope(gpu_cfg);
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::unsupported));
    BOOST_TEST(h.reports.last_outcome().command == 0x40U);

    BOOST_TEST(h.host.posted.empty());
    BOOST_TEST(h.router.stats().refused == 2U);
}

BOOST_AUTO_TEST_CASE(volume_lifecycle_delivers_the_key_and_cleans_on_detach,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    BOOST_TEST((h.keys.owner(vol_one) == vm_one));
    // The storage role keeps the wrapped key with the volume.
    BOOST_REQUIRE(h.blk_role.created.size() == 1U);
    const auto& stored = h.blk_role.created.at(0);
    BOOST_TEST(stored.volume == vol_one);
    BOOST_TEST(stored.owner == vm_one);
    BOOST_TEST(stored.capacity_sectors == size_gib * sectors_per_gib);
    BOOST_TEST(stored.block_size == oar::sector_size);
    const auto wrapped = h.keys.find_volume_key(vol_one);
    BOOST_REQUIRE(wrapped.has_value());
    BOOST_TEST(std::ranges::equal(stored.wrapped_key, wrapped->key.bytes()));

    const mb::AttachVolume attach{.volume_id = vol_one, .vm_id = vm_one, .device = blk(fn_one)};
    const auto a = h.send(attach);
    BOOST_REQUIRE(h.blk_role.prepared.size() == 1U);
    BOOST_TEST((h.blk_role.prepared.at(0).config ==
                oar::FunctionConfig{oar::BlkConfig{.volume_id = vol_one}}));
    BOOST_TEST((h.state(blk_slot, fn_one) == FunctionState::assigned));
    // The key waits for hull's answer: the VMM's open resets the function.
    BOOST_TEST(h.blk_role.keys.empty());
    h.answer(a, attach);
    BOOST_REQUIRE(h.blk_role.keys.size() == 1U);
    BOOST_TEST(h.blk_role.keys.at(0).first == fn_one);
    BOOST_TEST(h.blk_role.keys.at(0).second == vol_one);
    BOOST_TEST(h.host_faults().empty());

    // Deleting an attached volume is refused before hull sees it.
    const auto posted = h.host.posted.size();
    h.send(mb::DeleteVolume{.volume_id = vol_one});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));
    BOOST_TEST(h.host.posted.size() == posted);

    const mb::DetachVolume detach{.volume_id = vol_one,
                                  .vm_id = vm_one,
                                  .device = blk(fn_one),
                                  .timeout_s = detach_timeout_s,
                                  .policy = mb::DetachPolicy::force};
    h.run(detach);
    BOOST_TEST((h.state(blk_slot, fn_one) == FunctionState::releasing));
    BOOST_TEST(h.blk_role.cleaned.empty());  // not before hull's reset

    h.router.on_host_slot(host_slot(
        mb::DeviceReleased{.vm_id = vm_one, .device = blk(fn_one), .reset = mb::ResetResult::ok}));
    BOOST_REQUIRE(h.blk_role.cleaned.size() == 1U);
    BOOST_TEST((h.blk_role.cleaned.at(0).action == helm::CleaningAction::drop_volume_key));
    BOOST_TEST((h.state(blk_slot, fn_one) == FunctionState::free));

    // assigned -> releasing -> cleaning -> free, each reported once.
    const auto changes = h.reports.pool_changes();
    std::vector<proto::FunctionState> path;
    for (const auto& c : changes) {
        if (c.slot == blk_slot && c.function == fn_one) {
            path.push_back(c.to);
        }
    }
    BOOST_TEST((path == std::vector{proto::FunctionState::assigned, proto::FunctionState::releasing,
                                    proto::FunctionState::cleaning, proto::FunctionState::free}));

    BOOST_TEST(h.blk_role.deleted.empty());
    h.run(mb::DeleteVolume{.volume_id = vol_one});
    BOOST_TEST(!h.keys.owner(vol_one).has_value());
    BOOST_TEST(h.router.inventory().volumes.empty());
    BOOST_TEST((h.blk_role.deleted == std::vector<VolumeId>{vol_one}));
    BOOST_TEST(h.router.stats().storage_failures == 0U);
    const auto text = h.audit_text();
    BOOST_TEST(text.find("ev=volume_key_delivered seq=3 vm=101 vol=201 fn=2.1") !=
               std::string::npos);
    BOOST_TEST(text.find("ev=volume_key_destroyed seq=") != std::string::npos);
}

auto image_volume(VolumeId volume, VmId owner) -> mb::CreateVolume {
    mb::CreateVolume c{
        .volume_id = volume, .owner_vm = owner, .size_gib = size_gib, .image_store = 2};
    for (std::size_t i = 0; i < c.image_name.size(); ++i) {
        c.image_name[i] = static_cast<std::byte>(0x40 + i);
    }
    return c;
}

BOOST_AUTO_TEST_CASE(image_volumes_get_a_fresh_key_per_attachment,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVm{.vm_id = vm_two, .vcpus = vcpus, .memory_mib = memory_mib});
    const auto create = image_volume(vol_one, vm_one);
    h.run(create);
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
    // No volume key: the storage role gets the image source instead.
    BOOST_TEST(!h.keys.owner(vol_one).has_value());
    BOOST_TEST(h.keys.volume_count() == 0U);
    BOOST_REQUIRE(h.blk_role.created.size() == 1U);
    const auto& stored = h.blk_role.created.at(0);
    BOOST_TEST(stored.owner == vm_one);
    BOOST_TEST(stored.capacity_sectors == size_gib * sectors_per_gib);
    BOOST_TEST(stored.wrapped_key.empty());
    BOOST_TEST(stored.image_store == 2);
    BOOST_TEST((stored.image_name == create.image_name));
    BOOST_REQUIRE(h.router.inventory().volumes.size() == 1U);
    BOOST_TEST(h.router.inventory().volumes.at(0).owner_vm == vm_one);

    // A second create of the same ID, or for a VM helm does not know.
    h.send(image_volume(vol_one, vm_one));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));
    h.send(image_volume(vol_two, 0x999));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::unknown_vm));

    // Only the owner attaches it; the key comes after hull's answer.
    h.send(mb::AttachVolume{.volume_id = vol_one, .vm_id = vm_two, .device = blk(fn_one)});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));
    const mb::AttachVolume attach{.volume_id = vol_one, .vm_id = vm_one, .device = blk(fn_one)};
    const auto a = h.send(attach);
    BOOST_TEST(h.blk_role.keys.empty());
    h.answer(a, attach);
    BOOST_REQUIRE(h.blk_role.key_bytes.size() == 1U);
    BOOST_TEST(h.blk_role.key_bytes.at(0).size() == helm::volume_key_size);
    BOOST_TEST(h.host_faults().empty());
    BOOST_TEST(h.audit_text().find("ev=volume_key_delivered") != std::string::npos);
    // Image volumes cannot be rewrapped yet, nor deleted while attached.
    h.send(mb::RewrapVolume{.volume_id = vol_one, .from_vm = vm_one, .to_vm = vm_two});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::unsupported));
    h.send(mb::DeleteVolume{.volume_id = vol_one});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));

    const mb::DetachVolume detach{.volume_id = vol_one,
                                  .vm_id = vm_one,
                                  .device = blk(fn_one),
                                  .timeout_s = detach_timeout_s,
                                  .policy = mb::DetachPolicy::force};
    h.run(detach);
    h.router.on_host_slot(host_slot(
        mb::DeviceReleased{.vm_id = vm_one, .device = blk(fn_one), .reset = mb::ResetResult::ok}));
    BOOST_TEST((h.state(blk_slot, fn_one) == FunctionState::free));

    // The next attachment gets a different key: the last overlay stays unreadable.
    h.run(attach);
    BOOST_REQUIRE(h.blk_role.key_bytes.size() == 2U);
    BOOST_TEST((h.blk_role.key_bytes.at(0) != h.blk_role.key_bytes.at(1)));
    h.run(detach);
    h.router.on_host_slot(host_slot(
        mb::DeviceReleased{.vm_id = vm_one, .device = blk(fn_one), .reset = mb::ResetResult::ok}));

    // Delete: nothing to crypto-erase, the descriptor goes.
    h.run(mb::DeleteVolume{.volume_id = vol_one});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
    BOOST_TEST((h.blk_role.deleted == std::vector<VolumeId>{vol_one}));
    BOOST_TEST(h.router.inventory().volumes.empty());
    BOOST_TEST(h.router.stats().inconsistencies == 0U);
    BOOST_TEST(h.audit_text().find("ev=volume_key_destroyed") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(destroy_vm_deletes_its_image_volumes_unless_persisted,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVm{.vm_id = vm_two, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(image_volume(vol_one, vm_one));
    h.run(image_volume(vol_two, vm_two));
    h.run(mb::DestroyVm{.vm_id = vm_two, .persist_volumes = true});
    BOOST_TEST(h.blk_role.deleted.empty());
    BOOST_TEST(h.router.inventory().volumes.size() == 2U);
    h.run(mb::DestroyVm{.vm_id = vm_one});
    BOOST_TEST((h.blk_role.deleted == std::vector<VolumeId>{vol_one}));
    BOOST_REQUIRE(h.router.inventory().volumes.size() == 1U);
    BOOST_TEST(h.router.inventory().volumes.at(0).volume_id == vol_two);
}

BOOST_AUTO_TEST_CASE(a_refused_image_volume_is_not_relayed,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.blk_role.create_error =
        LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported};
    const auto posted = h.host.posted.size();
    h.send(image_volume(vol_one, vm_one));
    BOOST_TEST((status_of(h.reports.last_outcome()) != mb::Status::ok));
    BOOST_TEST(h.host.posted.size() == posted);
    BOOST_TEST(h.blk_role.deleted.empty());  // a refused create erases nothing
    BOOST_TEST(h.router.inventory().volumes.empty());
    Helm none{helm::RouterConfig{}.max_queued, false};
    none.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    none.send(image_volume(vol_one, vm_one));
    BOOST_TEST((status_of(none.reports.last_outcome()) == mb::Status::insufficient_resources));
}

BOOST_AUTO_TEST_CASE(a_failed_attach_is_compensated_and_the_function_cleaned,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    const mb::AttachVolume attach{.volume_id = vol_one, .vm_id = vm_one, .device = blk(fn_zero)};
    h.run(attach, mb::Status::insufficient_resources);

    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::insufficient_resources));
    // No key was sent; cleaning closes the volume the prepare opened.
    BOOST_TEST(h.blk_role.keys.empty());
    BOOST_REQUIRE(h.blk_role.cleaned.size() == 1U);
    BOOST_TEST((h.state(blk_slot, fn_zero) == FunctionState::free));
    // Not attached: the volume can be deleted.
    h.run(mb::DeleteVolume{.volume_id = vol_one});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
}

BOOST_AUTO_TEST_CASE(a_role_refusal_fails_the_command_before_hull,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.net_role.prepare_error = LinkError{.code = LinkErrc::refused, .status = oar::Status::busy};
    h.send(nic_attach(vm_one, fn_zero));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));
    BOOST_TEST(h.host.posted.empty());
    BOOST_TEST((h.state(net_slot, fn_zero) == FunctionState::free));
    BOOST_TEST(h.net_role.cleaned.size() == 1U);

    h.net_role.prepare_error = LinkError{.code = LinkErrc::timed_out};
    h.send(nic_attach(vm_one, fn_zero));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::timed_out));
}

BOOST_AUTO_TEST_CASE(nic_attach_configures_oar_net_from_the_command,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    // A NIC attach without its VPC, NIC ID and MAC does not decode: it is
    // refused as malformed and never reaches oar-net or hull.
    h.send(mb::AttachDevice{.vm_id = vm_one, .device = nic(fn_zero)});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::malformed));
    BOOST_TEST(h.net_role.prepared.empty());
    BOOST_TEST(h.host.posted.empty());
    BOOST_TEST((h.state(net_slot, fn_zero) == FunctionState::free));

    const auto attach = nic_attach(vm_one, fn_zero);
    h.run(attach);
    BOOST_REQUIRE(h.net_role.prepared.size() == 1U);
    BOOST_TEST((h.net_role.prepared.at(0).config == oar::FunctionConfig{test_nic_config()}));
    BOOST_TEST((h.state(net_slot, fn_zero) == FunctionState::assigned));

    // Already assigned: a second attach (to any VM) conflicts.
    h.send(nic_attach(vm_two, fn_zero));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));
    // Unknown function or a type that does not match the pool.
    h.send(nic_attach(vm_two, 9));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::unknown_device));
    auto wrong_slot = nic_attach(vm_two, fn_zero);
    wrong_slot.device.slot = blk_slot;
    h.send(wrong_slot);
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::unknown_device));
}

BOOST_AUTO_TEST_CASE(timeouts_report_and_keep_reservations,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    const auto attach = nic_attach(vm_one, fn_one);
    const auto a = h.send(attach);
    const mb::ListVms list{};
    const auto l = h.send(list);

    h.t += command_timeout - std::chrono::seconds{1};
    h.router.poll();
    BOOST_TEST(h.router.busy());
    h.t += std::chrono::seconds{1};
    h.router.poll();

    BOOST_TEST(h.router.stats().timed_out == 1U);
    const auto outcomes = h.reports.outcomes();
    BOOST_TEST(outcomes.back().in_reply_to == a);
    BOOST_TEST((status_of(outcomes.back()) == mb::Status::timed_out));
    // hull may have attached it: still held by the VM, not cleaned.
    BOOST_TEST((h.state(net_slot, fn_one) == FunctionState::assigned));
    BOOST_TEST(h.net_role.cleaned.empty());
    // The next command went out.
    BOOST_REQUIRE(h.host.posted.size() == 2U);
    BOOST_TEST((h.host.posted.at(1) == command_slot(l, list)));

    // hull's late answer is audited and changes nothing.
    h.answer(a, attach, mb::Status::conflict);
    BOOST_TEST((h.state(net_slot, fn_one) == FunctionState::assigned));
    BOOST_TEST(h.audit_text().find("ev=late_response seq=1") != std::string::npos);
    BOOST_TEST(h.router.busy());  // still waiting for LIST_VMS
}

BOOST_AUTO_TEST_CASE(destructive_steps_wait_for_hulls_ok,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVm{.vm_id = vm_two, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});

    // hull rejects the signature: nothing destroyed or moved.
    h.run(mb::DeleteVolume{.volume_id = vol_one}, mb::Status::bad_signature);
    BOOST_TEST((h.keys.owner(vol_one) == vm_one));
    h.run(mb::RewrapVolume{.volume_id = vol_one, .from_vm = vm_one, .to_vm = vm_two},
          mb::Status::bad_signature);
    BOOST_TEST((h.keys.owner(vol_one) == vm_one));
    h.run(mb::DestroyVm{.vm_id = vm_one, .persist_volumes = false}, mb::Status::bad_signature);
    BOOST_TEST(h.keys.find_vm_key(vm_one).has_value());
    BOOST_TEST(h.blk_role.deleted.empty());
    BOOST_TEST(h.blk_role.rewrapped.empty());

    // A rewrap that names the wrong current owner never reaches hull.
    const auto posted = h.host.posted.size();
    h.send(mb::RewrapVolume{.volume_id = vol_one, .from_vm = vm_two, .to_vm = vm_one});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));
    BOOST_TEST(h.host.posted.size() == posted);

    h.run(mb::RewrapVolume{.volume_id = vol_one, .from_vm = vm_one, .to_vm = vm_two});
    BOOST_TEST((h.keys.owner(vol_one) == vm_two));
    BOOST_TEST(h.router.inventory().volumes.at(0).owner_vm == vm_two);
    // The media gets the new owner and the re-wrapped key.
    BOOST_REQUIRE(h.blk_role.rewrapped.size() == 1U);
    BOOST_TEST(h.blk_role.rewrapped.at(0).volume == vol_one);
    BOOST_TEST(h.blk_role.rewrapped.at(0).owner == vm_two);
    const auto wrapped = h.keys.find_volume_key(vol_one);
    BOOST_REQUIRE(wrapped.has_value());
    BOOST_TEST(std::ranges::equal(h.blk_role.rewrapped.at(0).wrapped_key, wrapped->key.bytes()));
    BOOST_TEST(!std::ranges::equal(h.blk_role.created.at(0).wrapped_key, wrapped->key.bytes()));
}

BOOST_AUTO_TEST_CASE(a_failed_create_undoes_its_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib},
          mb::Status::insufficient_resources);
    BOOST_TEST(!h.keys.find_vm_key(vm_one).has_value());
    BOOST_TEST(h.router.inventory().vms.empty());

    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib},
          mb::Status::bad_signature);
    BOOST_TEST(!h.keys.owner(vol_one).has_value());
    // The volume stored for it is removed again.
    BOOST_TEST(h.blk_role.created.size() == 1U);
    BOOST_TEST((h.blk_role.deleted == std::vector<VolumeId>{vol_one}));

    // A volume for a VM helm has no key for is refused before hull.
    h.send(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_two, .size_gib = size_gib});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::unknown_vm));
}

BOOST_AUTO_TEST_CASE(destroy_vm_releases_functions_and_crypto_erases,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    h.run(mb::AttachVolume{.volume_id = vol_one, .vm_id = vm_one, .device = blk(fn_zero)});
    h.run(nic_attach(vm_one, fn_zero));

    // hull resets the NIC before helm has seen DESTROY_VM's response.
    const mb::DestroyVm destroy{.vm_id = vm_one, .persist_volumes = false};
    const auto d = h.send(destroy);
    h.router.on_host_slot(host_slot(
        mb::DeviceReleased{.vm_id = vm_one, .device = nic(fn_zero), .reset = mb::ResetResult::ok}));
    BOOST_TEST((h.state(net_slot, fn_zero) == FunctionState::free));
    h.answer(d, destroy);

    BOOST_TEST((h.state(blk_slot, fn_zero) == FunctionState::releasing));
    BOOST_TEST(!h.keys.find_vm_key(vm_one).has_value());
    BOOST_TEST(!h.keys.owner(vol_one).has_value());
    const auto inv = h.router.inventory();
    BOOST_TEST(inv.vms.empty());
    BOOST_TEST(inv.volumes.empty());
    // Crypto-erased, then released on the media.
    BOOST_TEST((h.blk_role.deleted == std::vector<VolumeId>{vol_one}));
    BOOST_TEST(h.audit_text().find("ev=vm_key_destroyed seq=5 vm=101 count=1") !=
               std::string::npos);
}

BOOST_AUTO_TEST_CASE(create_volume_needs_a_storage_role,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h{helm::RouterConfig{}.max_queued, false};
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    const auto posted = h.host.posted.size();
    h.send(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::insufficient_resources));
    BOOST_TEST(h.host.posted.size() == posted);
    BOOST_TEST(!h.keys.owner(vol_one).has_value());
}

BOOST_AUTO_TEST_CASE(a_refused_store_undoes_the_key_and_erases_nothing,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    // The role already has a file for this volume, say.
    h.blk_role.create_error = LinkError{.code = LinkErrc::refused, .status = oar::Status::failed};
    const auto posted = h.host.posted.size();
    h.send(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::internal_error));
    BOOST_TEST(h.host.posted.size() == posted);
    BOOST_TEST(!h.keys.owner(vol_one).has_value());
    BOOST_TEST(h.blk_role.deleted.empty());
}

BOOST_AUTO_TEST_CASE(a_volume_attaches_only_on_its_storage_slot,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    FakeOar other;
    h.router.add_slot(second_blk_slot, other, inventory(oar::Role::blk, FunctionType::blk_fn));
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    BOOST_TEST(h.blk_role.created.size() == 1U);  // the lowest blk slot
    BOOST_TEST(other.created.empty());

    const auto posted = h.host.posted.size();
    h.send(mb::AttachVolume{
        .volume_id = vol_one,
        .vm_id = vm_one,
        .device = {.slot = second_blk_slot, .type = mb::DeviceType::blk_fn, .function = fn_zero}});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::conflict));
    BOOST_TEST(h.host.posted.size() == posted);
    BOOST_TEST(other.prepared.empty());
}

BOOST_AUTO_TEST_CASE(a_lost_key_delivery_is_reported_as_a_host_fault,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    h.blk_role.deliver_error = LinkError{.code = LinkErrc::timed_out, .status = oar::Status::ok};
    const auto a =
        h.run(mb::AttachVolume{.volume_id = vol_one, .vm_id = vm_one, .device = blk(fn_one)});

    // hull attached it, so the outcome is hull's; the fault tells the
    // controller the disk has no key.
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
    BOOST_TEST((h.state(blk_slot, fn_one) == FunctionState::assigned));
    const auto faults = h.host_faults();
    BOOST_REQUIRE(faults.size() == 1U);
    BOOST_TEST((faults.at(0).code == proto::FaultCode::device_lost));
    BOOST_TEST(faults.at(0).slot == blk_slot);
    BOOST_TEST(faults.at(0).detail == vol_one);
    BOOST_TEST(h.router.stats().key_delivery_failures == 1U);
    BOOST_TEST(h.audit_text().find("ev=volume_key_delivery_failed seq=" + std::to_string(a) +
                                   " vm=101 vol=201 fn=2.1") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(media_failures_after_commit_are_counted,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVm{.vm_id = vm_two, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});

    h.blk_role.rewrap_error = LinkError{.code = LinkErrc::refused, .status = oar::Status::failed};
    h.run(mb::RewrapVolume{.volume_id = vol_one, .from_vm = vm_one, .to_vm = vm_two});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
    BOOST_TEST((h.keys.owner(vol_one) == vm_two));
    BOOST_TEST(h.router.stats().storage_failures == 1U);

    h.blk_role.delete_error = LinkError{.code = LinkErrc::disconnected, .status = oar::Status::ok};
    h.run(mb::DeleteVolume{.volume_id = vol_one});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
    BOOST_TEST(!h.keys.owner(vol_one).has_value());  // crypto-erased all the same
    BOOST_TEST(h.router.stats().storage_failures == 2U);
}

BOOST_AUTO_TEST_CASE(destroy_vm_with_persist_keeps_the_keys,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib});
    h.run(mb::CreateVolume{.volume_id = vol_one, .owner_vm = vm_one, .size_gib = size_gib});
    h.run(mb::AttachVolume{.volume_id = vol_one, .vm_id = vm_one, .device = blk(fn_zero)});
    h.run(mb::DestroyVm{.vm_id = vm_one, .persist_volumes = true});
    BOOST_TEST((h.keys.owner(vol_one) == vm_one));
    // The attachment ended with the VM.
    h.run(mb::DeleteVolume{.volume_id = vol_one});
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::ok));
}

BOOST_AUTO_TEST_CASE(stuck_releases_fault_until_a_power_cycle,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    const mb::DetachDevice detach{.vm_id = vm_one,
                                  .device = nic(fn_one),
                                  .timeout_s = detach_timeout_s,
                                  .policy = mb::DetachPolicy::force};
    h.run(nic_attach(vm_one, fn_one));
    h.run(detach);
    BOOST_TEST((h.state(net_slot, fn_one) == FunctionState::releasing));

    h.t += release_timeout;
    h.router.poll();
    BOOST_TEST((h.state(net_slot, fn_one) == FunctionState::faulted));
    BOOST_TEST((h.router.inventory().health == proto::Health::degraded));

    // A failed clean after the power cycle leaves it faulted ...
    h.net_role.clean_error = LinkError{.code = LinkErrc::refused, .status = oar::Status::failed};
    h.router.slot_power_cycled(net_slot);
    BOOST_TEST((h.state(net_slot, fn_one) == FunctionState::faulted));
    // ... a good one frees it.
    h.net_role.clean_error.reset();
    h.router.slot_power_cycled(net_slot);
    BOOST_TEST((h.state(net_slot, fn_one) == FunctionState::free));
    BOOST_TEST((h.router.inventory().health == proto::Health::ok));
}

BOOST_AUTO_TEST_CASE(gpu_cleaning_waits_for_scrub_done,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    const mb::DetachDevice detach{.vm_id = vm_one,
                                  .device = gpu(fn_zero),
                                  .timeout_s = detach_timeout_s,
                                  .policy = mb::DetachPolicy::force};
    h.run(mb::AttachDevice{.vm_id = vm_one, .device = gpu(fn_zero)});
    h.run(detach);
    h.router.on_host_slot(host_slot(
        mb::DeviceReleased{.vm_id = vm_one, .device = gpu(fn_zero), .reset = mb::ResetResult::ok}));
    BOOST_TEST((h.state(gpu_slot, fn_zero) == FunctionState::cleaning));
    BOOST_TEST(h.gpu_role.cleaned.empty());
    h.router.on_host_slot(
        host_slot(mb::ScrubDone{.device = gpu(fn_zero), .result = mb::ScrubResult::ok}));
    BOOST_TEST((h.state(gpu_slot, fn_zero) == FunctionState::free));

    // And a scrub that never comes faults the function.
    h.run(mb::AttachDevice{.vm_id = vm_one, .device = gpu(fn_one)});
    h.run(mb::DetachDevice{.vm_id = vm_one,
                           .device = gpu(fn_one),
                           .timeout_s = detach_timeout_s,
                           .policy = mb::DetachPolicy::force});
    h.router.on_host_slot(host_slot(
        mb::DeviceReleased{.vm_id = vm_one, .device = gpu(fn_one), .reset = mb::ResetResult::ok}));
    h.t += clean_timeout;
    h.router.poll();
    BOOST_TEST((h.state(gpu_slot, fn_one) == FunctionState::faulted));
}

BOOST_AUTO_TEST_CASE(failed_resets_fault_and_events_are_reported,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(nic_attach(vm_one, fn_zero));
    h.run(mb::DetachDevice{.vm_id = vm_one,
                           .device = nic(fn_zero),
                           .timeout_s = detach_timeout_s,
                           .policy = mb::DetachPolicy::force});
    h.router.on_host_slot(host_slot(mb::DeviceReleased{
        .vm_id = vm_one, .device = nic(fn_zero), .reset = mb::ResetResult::failed}));
    BOOST_TEST((h.state(net_slot, fn_zero) == FunctionState::faulted));

    // A DEVICE_RELEASED naming the wrong VM changes nothing.
    h.run(nic_attach(vm_one, fn_one));
    h.router.on_host_slot(host_slot(
        mb::DeviceReleased{.vm_id = vm_two, .device = nic(fn_one), .reset = mb::ResetResult::ok}));
    BOOST_TEST((h.state(net_slot, fn_one) == FunctionState::assigned));
    BOOST_TEST(h.router.stats().inconsistencies == 1U);

    h.reports.all.clear();
    h.router.on_host_slot(host_slot(
        mb::VmExited{.vm_id = vm_one, .exit_status = 1, .reason = mb::ExitReason::guest_fault}));
    h.router.on_host_slot(host_slot(
        mb::HostFault{.code = mb::FaultCode::device_lost, .slot = net_slot, .detail = 0}));
    h.router.on_map_applied(vni, 3);
    BOOST_REQUIRE(h.reports.all.size() == 3U);
    BOOST_TEST(std::get<proto::VmExitedReport>(h.reports.all.at(0)).vm_id == vm_one);
    BOOST_TEST(std::get<proto::HostFaultReport>(h.reports.all.at(1)).slot == net_slot);
    BOOST_TEST(std::get<proto::MapApplied>(h.reports.all.at(2)).map_version == 3U);
    BOOST_TEST(h.router.inventory().networks.at(0).map_version == 3U);

    // Garbage from hull is counted, never acted on.
    mb::Slot junk{};
    h.router.on_host_slot(junk);
    BOOST_TEST(h.router.stats().stray_messages == 1U);
}

BOOST_AUTO_TEST_CASE(a_mailbox_write_failure_is_compensated,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.host.fail = true;
    h.send(nic_attach(vm_one, fn_zero));
    BOOST_TEST((status_of(h.reports.last_outcome()) == mb::Status::internal_error));
    BOOST_TEST((h.state(net_slot, fn_zero) == FunctionState::free));
    BOOST_TEST(!h.router.busy());
}

BOOST_AUTO_TEST_CASE(inventory_lists_every_function,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Helm h;
    h.run(nic_attach(vm_one, fn_one));
    const auto inv = h.router.inventory();
    BOOST_TEST(inv.functions.size() == 6U);
    const auto it = std::ranges::find_if(inv.functions, [](const proto::InventoryFunction& f) {
        return f.slot == net_slot && f.function == fn_one;
    });
    BOOST_REQUIRE(it != inv.functions.end());
    BOOST_TEST((it->state == proto::FunctionState::assigned));
    BOOST_TEST(it->owner_vm == vm_one);
    BOOST_TEST((it->type == proto::FunctionType::nic_vf));
    // A complete inventory encodes (the session sets boot_id).
    auto with_boot = inv;
    with_boot.boot_id = 1;
    BOOST_TEST(proto::encode_report({.server_id = server, .report_seq = 1, .body = with_boot})
                   .has_value());
}
