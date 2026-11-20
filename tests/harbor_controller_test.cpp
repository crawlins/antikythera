// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ task 5: harbor's test controller. Its
// signer must reproduce the published signing vectors and satisfy hull's
// verifier; its script parser must reject what hull would; and it must
// drive a real ControllerLink end to end.

#define BOOST_TEST_MODULE harbor_controller_test
#include <boost/test/unit_test.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ed25519_test_support.hpp"
#include "harbor/test_controller.hpp"
#include "helm/controller_link.hpp"
#include "helm/mailbox.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/test_vectors.hpp"
#include "test_support.hpp"
#include "tls_test_support.hpp"

namespace harbor = ak::harbor;
namespace helm = ak::helm;
namespace hull = ak::hull;
namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
namespace tls = ak::tls;
namespace vectors = ak::proto::vectors;
using ak::test::from_hex;
using namespace std::chrono_literals;

namespace {

constexpr unsigned timeout_seconds = 60;
const std::string loopback = "127.0.0.1";

struct IgnoreSigpipe {
    IgnoreSigpipe() { (void)std::signal(SIGPIPE, SIG_IGN); }
};
const IgnoreSigpipe ignore_sigpipe;

auto signer_for(std::string_view secret_hex) -> harbor::Signer {
    const auto secret = ak::test::fixed_from_hex<harbor::ed25519_secret_size>(secret_hex);
    auto s = harbor::Signer::from_raw(secret);
    BOOST_REQUIRE(s.has_value());
    return std::move(*s);
}

auto verifier() -> hull::SignatureVerifier {
    const std::array keys{ak::test::controller_key(1, vectors::key1_public),
                          ak::test::controller_key(2, vectors::key2_public)};
    auto v = hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(v.has_value());
    return std::move(*v);
}

auto action(std::string_view line) -> harbor::Action {
    auto a = harbor::parse_line(line);
    BOOST_REQUIRE_MESSAGE(a.has_value(), std::string{line} + ": " + (a ? "" : a.error()));
    BOOST_REQUIRE(a->has_value());
    return **a;
}

auto parse_error(std::string_view line) -> std::string {
    auto a = harbor::parse_line(line);
    BOOST_REQUIRE_MESSAGE(!a.has_value(), std::string{line} + " parsed");
    return a.error();
}

auto body_of(std::string_view line) -> mb::Body {
    auto a = action(line);
    BOOST_REQUIRE(std::holds_alternative<harbor::SendCommand>(a));
    return std::get<harbor::SendCommand>(a).body;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(signer, *boost::unit_test::timeout(timeout_seconds))

BOOST_AUTO_TEST_CASE(reproduces_the_envelope_vector) {
    const auto s = signer_for(vectors::key1_secret);
    auto env =
        s.envelope(vectors::envelope1_server_id, vectors::envelope1_key_id, vectors::envelope1_seq,
                   mb::CreateVm{.vm_id = vectors::envelope1_vm_id,
                                .vcpus = vectors::envelope1_vcpus,
                                .memory_mib = vectors::envelope1_memory_mib,
                                .boot_mode = mb::BootMode::volume});
    BOOST_REQUIRE(env.has_value());
    BOOST_TEST((std::vector<std::byte>(env->begin(), env->end()) == from_hex(vectors::envelope1)));
}

BOOST_AUTO_TEST_CASE(reproduces_the_map_update_vector) {
    const auto s = signer_for(vectors::key1_secret);
    auto want = proto::decode_map_update(from_hex(vectors::map2));
    BOOST_REQUIRE(want.has_value());
    auto unsigned_update = *want;
    unsigned_update.signature = {};
    auto got = s.map_update(unsigned_update);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == from_hex(vectors::map2)));
}

BOOST_AUTO_TEST_CASE(every_command_verifies_under_hull) {
    const auto s = signer_for(vectors::key2_secret);
    const auto v = verifier();
    std::uint64_t seq = 1;
    for (const auto* line :
         {"list-vms", "vm-status 7", "create-vm 7 2 1024", "destroy-vm 7 persist",
          "attach-device 7 1 nic 0 0x55 0x10 02:00:00:00:00:10", "attach-device 7 3 gpu 1",
          "detach-device 7 1 nic 0 30 force", "create-volume 9 7 20", "delete-volume 9",
          "attach-volume 9 7 2 0", "detach-volume 9 7 2 0 30 destroy-vm", "rewrap-volume 9 7 8",
          "create-network 0x55", "delete-network 0x55"}) {
        auto env = s.envelope(7, 2, seq++, body_of(line));
        BOOST_REQUIRE_MESSAGE(env.has_value(), line);
        auto decoded = proto::decode_envelope(*env);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_TEST(v.verify_slot(decoded->slot, 2).has_value(), line);
        BOOST_TEST(!v.verify_slot(decoded->slot, 1).has_value(), line);
        auto msg = mb::decode(decoded->slot);
        BOOST_REQUIRE(msg.has_value());
        BOOST_TEST(mb::decode_body(*msg).has_value(), line);
        BOOST_TEST(msg->header.server_id == 7U, line);
    }
}

BOOST_AUTO_TEST_CASE(loads_a_pem_key_and_refuses_other_kinds) {
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ed{
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), &EVP_PKEY_free};
    BOOST_REQUIRE(ed != nullptr);
    const auto pem = ak::test::detail::to_pem(ed.get());
    auto s = harbor::Signer::from_pem(pem);
    BOOST_REQUIRE(s.has_value());
    const auto msg = ak::test::bytes_of(1, 2, 3);
    BOOST_TEST(s->sign(msg).has_value());

    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ec{EVP_EC_gen("P-256"),
                                                                 &EVP_PKEY_free};
    BOOST_TEST(!harbor::Signer::from_pem(ak::test::detail::to_pem(ec.get())).has_value());
    BOOST_TEST(!harbor::Signer::from_pem("garbage").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(script, *boost::unit_test::timeout(timeout_seconds))

BOOST_AUTO_TEST_CASE(blank_lines_and_comments_are_nothing) {
    for (const auto* line : {"", "   ", "# a comment", "\t# indented"}) {
        auto a = harbor::parse_line(line);
        BOOST_REQUIRE(a.has_value());
        BOOST_TEST(!a->has_value());
    }
}

BOOST_AUTO_TEST_CASE(commands_parse_to_their_bodies) {
    BOOST_TEST(
        (body_of("create-vm 0x1001 4 8192  # boot from volume") ==
         mb::Body{mb::CreateVm{
             .vm_id = 0x1001, .vcpus = 4, .memory_mib = 8192, .boot_mode = mb::BootMode::volume}}));
    BOOST_TEST((body_of("destroy-vm 7") == mb::Body{mb::DestroyVm{.vm_id = 7}}));
    BOOST_TEST((body_of("detach-device 7 3 gpu-vf 2 60 destroy-vm") ==
                mb::Body{mb::DetachDevice{
                    .vm_id = 7,
                    .device = {.slot = 3, .type = mb::DeviceType::gpu_vf, .function = 2},
                    .timeout_s = 60,
                    .policy = mb::DetachPolicy::destroy_vm}}));
    BOOST_TEST((body_of("attach-device 7 1 nic 2 0x55 0x10 02:00:00:00:00:10") ==
                mb::Body{mb::AttachDevice{
                    .vm_id = 7,
                    .device = {.slot = 1, .type = mb::DeviceType::nic_vf, .function = 2},
                    .vni = 0x55,
                    .nic_id = 0x10,
                    .mac = {std::byte{2}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                            std::byte{0x10}}}}));
    BOOST_TEST((body_of("destroy-vm 7 persist") ==
                mb::Body{mb::DestroyVm{.vm_id = 7, .persist_volumes = true}}));
    {
        mb::CreateVolume image{.volume_id = 9, .owner_vm = 7, .size_gib = 4, .image_store = 3};
        for (std::size_t i = 0; i < image.image_name.size(); ++i) {
            image.image_name[i] = static_cast<std::byte>(0xA0 + i);
        }
        BOOST_TEST((body_of("create-volume 9 7 4 3 "
                            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf") ==
                    mb::Body{image}));
    }
    BOOST_TEST((body_of("attach-volume 9 7 2 1") ==
                mb::Body{mb::AttachVolume{
                    .volume_id = 9,
                    .vm_id = 7,
                    .device = {.slot = 2, .type = mb::DeviceType::blk_fn, .function = 1}}}));
}

BOOST_AUTO_TEST_CASE(map_updates_parse_and_sort) {
    auto a =
        action("map-update 5 2 0x11,02:00:00:00:00:11,10.0.0.2 0x10,02:00:00:00:00:10,fd00::1");
    BOOST_REQUIRE(std::holds_alternative<harbor::SendMapUpdate>(a));
    const auto& m = std::get<harbor::SendMapUpdate>(a);
    BOOST_TEST(m.vni == 5U);
    BOOST_TEST(m.map_version == 2U);
    BOOST_REQUIRE(m.entries.size() == 2U);
    BOOST_TEST(m.entries[0].nic_id == 0x10U);
    BOOST_TEST(std::to_integer<int>(m.entries[0].owner_vtep[0]) == 0xFD);
    BOOST_TEST(std::to_integer<int>(m.entries[1].owner_vtep[10]) == 0xFF);  // IPv4-mapped
    BOOST_TEST(std::to_integer<int>(m.entries[1].owner_vtep[15]) == 2);
    BOOST_TEST(std::to_integer<int>(m.entries[1].mac[5]) == 0x11);
    BOOST_TEST(m.ipv4.empty());
    BOOST_TEST(m.ipv6.empty());

    // Guest addresses follow the VTEP, sorted into the frame's order.
    auto g = action(
        "map-update 5 3 0x11,02:00:00:00:00:11,fd00::2,10.0.0.9,fd12::11 "
        "0x10,02:00:00:00:00:10,fd00::1,10.0.0.8,10.0.0.7");
    const auto& gm = std::get<harbor::SendMapUpdate>(g);
    BOOST_REQUIRE(gm.ipv4.size() == 3U);
    BOOST_TEST(std::to_integer<int>(gm.ipv4[0].address[3]) == 7);
    BOOST_TEST(gm.ipv4[0].nic_id == 0x10U);
    BOOST_TEST(gm.ipv4[2].nic_id == 0x11U);
    BOOST_REQUIRE(gm.ipv6.size() == 1U);
    BOOST_TEST(gm.ipv6[0].nic_id == 0x11U);
    BOOST_TEST(std::to_integer<int>(gm.ipv6[0].address[1]) == 0x12);
}

BOOST_AUTO_TEST_CASE(expectations_parse) {
    auto e = action("expect stale_sequence");
    BOOST_TEST((std::get<harbor::ExpectOutcome>(e).status == proto::CommandStatus::stale_sequence));
    auto ws = action("expect wrong_server");
    BOOST_TEST((std::get<harbor::ExpectOutcome>(ws).status == proto::CommandStatus::wrong_server));
    auto w = action("wait map_applied");
    BOOST_TEST((std::get<harbor::WaitReport>(w).kind == proto::ReportKind::map_applied));
}

BOOST_AUTO_TEST_CASE(mistakes_are_named) {
    BOOST_TEST(parse_error("launch 7").find("unknown action") != std::string::npos);
    BOOST_TEST(parse_error("create-vm 7 2").find("wrong number") != std::string::npos);
    BOOST_TEST(parse_error("create-vm x 2 1024").find("bad VM id") != std::string::npos);
    BOOST_TEST(parse_error("vm-status 0x").find("bad VM id") != std::string::npos);
    BOOST_TEST(parse_error("attach-device 7 1 disk 0").find("device type") != std::string::npos);
    // A NIC needs its VPC, NIC ID and MAC; a GPU takes none.
    BOOST_TEST(parse_error("attach-device 7 1 nic 0").find("invalid command") != std::string::npos);
    BOOST_TEST(parse_error("attach-device 7 1 nic 0 0x55 0x10").find("wrong number") !=
               std::string::npos);
    BOOST_TEST(parse_error("attach-device 7 1 nic 0 0x55 0x10 01:00:00:00:00:10")
                   .find("invalid command") != std::string::npos);
    BOOST_TEST(parse_error("attach-device 7 1 nic 0 0x55 0x10 02:00").find("MAC") !=
               std::string::npos);
    BOOST_TEST(parse_error("attach-device 7 3 gpu 0 0x55 0x10 02:00:00:00:00:10")
                   .find("invalid command") != std::string::npos);
    BOOST_TEST(parse_error("destroy-vm 7 keep").find("persist") != std::string::npos);
    BOOST_TEST(parse_error("create-volume 9 7 4 3").find("wrong number") != std::string::npos);
    BOOST_TEST(parse_error("create-volume 9 7 4 3 a0a1").find("image name") != std::string::npos);
    // An image store with an all-zero name is refused before it is sent.
    BOOST_TEST(
        parse_error("create-volume 9 7 4 3 " + std::string(64, '0')).find("invalid command") !=
        std::string::npos);
    BOOST_TEST(parse_error("expect fine").find("unknown status") != std::string::npos);
    BOOST_TEST(parse_error("wait forever").find("unknown report kind") != std::string::npos);
    BOOST_TEST(parse_error("map-update 5").find("map-update") != std::string::npos);
    BOOST_TEST(parse_error("map-update 5 1 0x10,02:00:00:00:00,fd00::1").find("MAC") !=
               std::string::npos);
    BOOST_TEST(parse_error("map-update 5 1 0x10,02:00:00:00:00:10,nowhere").find("VTEP") !=
               std::string::npos);
    BOOST_TEST(parse_error("map-update 5 1 0x10").find("NIC,MAC,VTEP") != std::string::npos);
    BOOST_TEST(parse_error("map-update 5 1 0x10,02:00:00:00:00:10,fd00::1,10.0.0.300")
                   .find("guest address") != std::string::npos);
    // Values hull's strict decoder refuses fail here, not as `malformed`.
    BOOST_TEST(parse_error("create-network 0").find("invalid command") != std::string::npos);
    BOOST_TEST(parse_error("create-network 0x1000000").find("invalid command") !=
               std::string::npos);
    BOOST_TEST(parse_error("detach-device 7 1 nic 0 0 force").find("invalid command") !=
               std::string::npos);
    BOOST_TEST(parse_error("create-vm 99999999999999999999 1 1").find("bad VM id") !=
               std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

// A helm stand-in behind a real ControllerLink: verifies each envelope
// the way hull will and reports the outcome; reports every mapping update
// as applied. It runs on the link's thread, where Boost.Test assertions
// are not safe, so it records problems for the test thread to check.
struct FakeHelm final : helm::ControllerSink {
    hull::SignatureVerifier verify = verifier();
    helm::ControllerLink* link = nullptr;
    std::atomic<std::uint64_t> last_seq{0};
    std::atomic<int> problems{0};

    auto on_envelope(const proto::Envelope& env) -> void override {
        auto msg = mb::decode(env.slot);
        if (!msg) {
            ++problems;
            return;
        }
        auto status = proto::CommandStatus::ok;
        if (!verify.verify_slot(env.slot, msg->header.key_id)) {
            status = proto::CommandStatus::bad_signature;
        } else if (msg->header.seq <= last_seq) {
            status = proto::CommandStatus::stale_sequence;
        } else {
            last_seq = msg->header.seq;
        }
        (void)link->report(
            proto::CommandOutcome{.in_reply_to = msg->header.seq,
                                  .command = static_cast<std::uint16_t>(msg->header.type),
                                  .status = status,
                                  .payload = {}});
    }
    auto on_map_update(const proto::MapUpdate& u, std::span<const std::byte> frame)
        -> void override {
        const auto sig = std::span<const std::byte, 64>{frame.last<64>()};
        const auto ok = verify.verify(proto::map_update_signed_bytes(frame), sig, u.key_id);
        if (!ok) {
            ++problems;
        }
        (void)link->report(proto::MapApplied{.vni = u.vni, .map_version = u.map_version});
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(end_to_end, *boost::unit_test::timeout(timeout_seconds))

BOOST_AUTO_TEST_CASE(drives_a_controller_link) {
    ak::test::TestCa controller_ca{"kythira test CA"};
    ak::test::TestCa server_ca{"server CA"};
    const auto controller_cert = controller_ca.issue("controller", "IP:127.0.0.1");
    const auto helm_cert = server_ca.issue("server-7", "DNS:server-7");
    constexpr std::uint64_t server = 7;

    std::vector<std::string> printed;
    auto controller = harbor::TestController::create(
        {.tls = {.role = tls::Role::server,
                 .ca_pem = server_ca.cert_pem(),
                 .cert_pem = controller_cert.cert,
                 .key_pem = controller_cert.key,
                 .peer_name = "server-7"},
         .server_id = server,
         .key_id = 1,
         .timeout = 10s,
         .on_report = [&](const proto::Report& r) { printed.push_back(harbor::to_string(r)); }},
        signer_for(vectors::key1_secret));
    BOOST_REQUIRE_MESSAGE(controller.has_value(),
                          (controller ? std::string{} : controller.error()));
    auto listener = tls::Listener::bind(loopback, 0);
    BOOST_REQUIRE(listener.has_value());

    FakeHelm fake;
    helm::ControllerSession session{server, 0xB007,
                                    [] {
                                        proto::Inventory inv;
                                        inv.boot_id = 1;
                                        inv.last_command_seq = 40;  // hull saw up to 40
                                        return inv;
                                    },
                                    fake};
    fake.last_seq = 40;
    auto link = helm::ControllerLink::create({.host = loopback,
                                              .port = listener->port(),
                                              .tls = {.role = tls::Role::client,
                                                      .ca_pem = controller_ca.cert_pem(),
                                                      .cert_pem = helm_cert.cert,
                                                      .key_pem = helm_cert.key,
                                                      .peer_name = loopback},
                                              .min_backoff = 20ms,
                                              .max_backoff = 100ms,
                                              .io_timeout = 5s},
                                             session);
    BOOST_REQUIRE(link.has_value());
    fake.link = link->get();
    std::jthread runner{[&](const std::stop_token& st) { (*link)->run(st); }};

    auto registered = controller->accept(*listener);
    BOOST_REQUIRE_MESSAGE(registered.has_value(),
                          (registered ? std::string{} : registered.error()));
    BOOST_TEST(controller->boot_id() == 0xB007U);
    BOOST_TEST(controller->next_seq() == 41U);  // resumes after hull's last

    for (const auto* line :
         {"create-network 5", "expect ok", "create-vm 0x1001 2 1024", "expect ok",
          "map-update 5 1 0x10,02:00:00:00:00:10,fd00::1", "wait map_applied"}) {
        auto ok = controller->run(action(line));
        BOOST_REQUIRE_MESSAGE(ok.has_value(), std::string{line} + ": " + (ok ? "" : ok.error()));
    }
    BOOST_TEST(fake.last_seq.load() == 42U);
    BOOST_TEST(fake.problems.load() == 0);

    // A wrong expectation fails with a message naming both statuses.
    auto wrong = controller->run(action("list-vms"));
    BOOST_REQUIRE(wrong.has_value());
    auto mismatch = controller->run(action("expect conflict"));
    BOOST_REQUIRE(!mismatch.has_value());
    BOOST_TEST(mismatch.error().find("got ok, wanted conflict") != std::string::npos);

    BOOST_TEST(printed.size() >= 4U);
    BOOST_TEST(printed.front().find("kind=inventory") != std::string::npos);
    runner.request_stop();
}

BOOST_AUTO_TEST_CASE(refuses_bad_options) {
    ak::test::TestCa ca{"CA"};
    const auto cert = ca.issue("controller", "IP:127.0.0.1");
    const tls::Config cfg{.role = tls::Role::server,
                          .ca_pem = ca.cert_pem(),
                          .cert_pem = cert.cert,
                          .key_pem = cert.key,
                          .peer_name = ""};
    const auto opts = [](const tls::Config& c, std::uint64_t server, proto::KeyId key) {
        return harbor::ControllerOptions{
            .tls = c, .server_id = server, .key_id = key, .timeout = 1s, .on_report = {}};
    };
    BOOST_TEST(!harbor::TestController::create(opts(cfg, 0, 1), signer_for(vectors::key1_secret))
                    .has_value());
    BOOST_TEST(!harbor::TestController::create(opts(cfg, 1, 0), signer_for(vectors::key1_secret))
                    .has_value());
    auto bad = cfg;
    bad.key_pem = "nope";
    BOOST_TEST(!harbor::TestController::create(opts(bad, 1, 1), signer_for(vectors::key1_secret))
                    .has_value());
}

BOOST_AUTO_TEST_SUITE_END()
