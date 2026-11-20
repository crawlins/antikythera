// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirements 1, 3.5 and 10.1: every
// command, response and event body.

#define BOOST_TEST_MODULE mailbox_bodies_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "helm/mailbox.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using mb::BodyError;

namespace {

constexpr std::uint64_t sample_seq = 9;
constexpr std::uint64_t vm_a = 0x1111'2222'3333'4444;
constexpr std::uint64_t vm_b = 7;
constexpr std::uint64_t volume = 0x55;
constexpr std::uint32_t volume_gib = 100;
constexpr std::uint32_t vni = 0xAB'CDEF;
constexpr std::uint16_t timeout_s = 30;
constexpr std::uint32_t exit_status = 0x8000'0001;
constexpr std::uint64_t fault_detail = 0xDEAD'BEEF'0000'1000;
constexpr std::uint8_t fault_slot = 3;
constexpr std::uint16_t sample_vcpus = 2;
constexpr std::uint32_t sample_memory_mib = 4096;

constexpr mb::DeviceRef nic{.slot = 2, .type = mb::DeviceType::nic_vf, .function = 0x0102};
constexpr mb::DeviceRef blk{.slot = 4, .type = mb::DeviceType::blk_fn, .function = 1};
constexpr mb::DeviceRef gpu{.slot = 6, .type = mb::DeviceType::gpu_vf, .function = 9};

// Body offsets used to corrupt one field at a time.
constexpr std::size_t after_vm_id = 8;
constexpr std::size_t after_two_ids = 16;
constexpr std::size_t device_type_in_ref = 1;
constexpr std::size_t timeout_in_tail = 4;  // offsets from the start of the device ref
constexpr std::size_t policy_in_tail = 6;
constexpr std::size_t rsvd_in_tail = 7;

constexpr std::byte zero{0};
constexpr std::byte nonzero{1};
constexpr std::byte bad_device_type{5};
constexpr std::byte bad_policy{3};
constexpr std::uint8_t too_long_timeout = 0x59;  // low byte of 601 (0x0259)
constexpr std::uint8_t too_long_timeout_hi = 0x02;

constexpr mb::KeyId sample_key = 1;
constexpr mb::ServerId sample_server = 7;
constexpr std::uint64_t nic_id = 0x10;
constexpr mb::Mac guest_mac{std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
                            std::byte{0x00}, std::byte{0x00}, std::byte{0x10}};

// ATTACH_DEVICE body offsets past the device ref (protocol v3).
constexpr std::size_t attach_vni = 12;
constexpr std::size_t attach_nic_id = 16;
constexpr std::size_t attach_mac = 24;
constexpr std::size_t attach_rsvd = 30;
constexpr std::byte multicast_mac{0x03};  // locally administered but multicast
constexpr std::byte vendor_mac{0x00};     // unicast but universally administered
constexpr std::uint16_t image_store = 3;
constexpr std::size_t image_store_offset = 20;  // in an image CREATE_VOLUME
constexpr std::size_t image_name_offset = 24;
constexpr std::size_t image_volume_body_len = 56;

auto sig() -> std::array<std::byte, mb::signature_size> {
    return {};
}

auto message(mb::Type type, std::span<const std::byte> body) -> mb::Message {
    mb::Header h;
    h.type = type;
    h.seq = sample_seq;
    h.body_len = static_cast<std::uint16_t>(body.size());
    // Commands name their signing key and server, responses and events don't.
    h.key_id = mb::is_command(type) ? sample_key : mb::no_key_id;
    h.server_id = mb::is_command(type) ? sample_server : mb::no_server_id;
    auto slot = mb::encode(h, body, sig());
    BOOST_REQUIRE(slot.has_value());
    auto msg = mb::decode(*slot);
    BOOST_REQUIRE(msg.has_value());
    return *msg;
}

auto message(const mb::Body& body) -> mb::Message {
    return message(mb::type_of(body), mb::encode_body(body));
}

auto decode_error(mb::Type type, std::span<const std::byte> body) -> BodyError {
    auto r = mb::decode_body(message(type, body));
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

// Encodes a valid body, overwrites one byte, and expects invalid_field.
auto expect_invalid(const mb::Body& body, std::size_t offset, std::byte value) -> void {
    auto bytes = mb::encode_body(body);
    BOOST_REQUIRE(offset < bytes.size());
    bytes[offset] = value;
    BOOST_TEST((decode_error(mb::type_of(body), bytes) == BodyError::invalid_field));
}

auto nic_attach() -> mb::AttachDevice {
    return {.vm_id = vm_a, .device = nic, .vni = vni, .nic_id = nic_id, .mac = guest_mac};
}

auto image_volume() -> mb::CreateVolume {
    mb::ImageName name{};
    name.fill(std::byte{0x5A});
    name[0] = std::byte{0x01};
    return {.volume_id = volume,
            .owner_vm = vm_a,
            .size_gib = volume_gib,
            .image_store = image_store,
            .image_name = name};
}

auto ok_response() -> mb::Response {
    mb::Response r;
    r.in_reply_to = sample_seq;
    r.command = mb::Type::attach_device;
    r.status = mb::Status::accepted;
    return r;
}

auto every_body() -> std::vector<mb::Body> {
    mb::Response with_payload;
    with_payload.in_reply_to = sample_seq;
    with_payload.command = mb::Type::list_vms;
    with_payload.status = mb::Status::ok;
    with_payload.payload_len = 3;
    with_payload.payload[0] = std::byte{0xAA};
    with_payload.payload[2] = std::byte{0xCC};

    mb::Response full_payload = with_payload;
    full_payload.payload_len = mb::max_response_payload;

    return {
        mb::ListVms{},
        mb::VmStatus{.vm_id = vm_a},
        mb::CreateVm{.vm_id = vm_a, .vcpus = sample_vcpus, .memory_mib = sample_memory_mib},
        mb::DestroyVm{.vm_id = vm_a, .persist_volumes = true},
        nic_attach(),
        mb::AttachDevice{.vm_id = vm_a, .device = gpu},
        mb::DetachDevice{.vm_id = vm_a,
                         .device = nic,
                         .timeout_s = timeout_s,
                         .policy = mb::DetachPolicy::destroy_vm},
        mb::CreateVolume{.volume_id = volume, .owner_vm = vm_a, .size_gib = volume_gib},
        mb::CreateVolume{.volume_id = volume, .owner_vm = vm_a, .size_gib = mb::max_volume_gib},
        image_volume(),
        mb::DeleteVolume{.volume_id = volume},
        mb::AttachVolume{.volume_id = volume, .vm_id = vm_a, .device = blk},
        mb::DetachVolume{.volume_id = volume,
                         .vm_id = vm_a,
                         .device = blk,
                         .timeout_s = mb::max_detach_timeout_s,
                         .policy = mb::DetachPolicy::force},
        mb::RewrapVolume{.volume_id = volume, .from_vm = vm_a, .to_vm = vm_b},
        mb::CreateNetwork{.vni = vni},
        mb::DeleteNetwork{.vni = mb::max_vni},
        ok_response(),
        with_payload,
        full_payload,
        mb::VmExited{
            .vm_id = vm_a, .exit_status = exit_status, .reason = mb::ExitReason::vmm_failure},
        mb::DeviceReleased{.vm_id = vm_a, .device = nic, .reset = mb::ResetResult::failed},
        mb::HostFault{
            .code = mb::FaultCode::iommu_fault, .slot = fault_slot, .detail = fault_detail},
        mb::HostFault{.code = mb::FaultCode::agent_restarted},
        mb::ScrubDone{.device = gpu, .result = mb::ScrubResult::ok},
    };
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_body_round_trips, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto& body : every_body()) {
        const auto msg = message(body);
        auto decoded = mb::decode_body(msg);
        BOOST_REQUIRE_MESSAGE(decoded.has_value(), "type " << std::to_underlying(mb::type_of(body))
                                                           << ": "
                                                           << mb::to_string(decoded.error()));
        BOOST_TEST((*decoded == body));
        BOOST_TEST((mb::encode_body(*decoded) ==
                    std::vector<std::byte>(msg.body_bytes().begin(), msg.body_bytes().end())));
    }
}

BOOST_AUTO_TEST_CASE(commands_and_events_classify,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(mb::is_command(mb::type_of(mb::AttachVolume{})));
    BOOST_TEST(mb::is_command(mb::type_of(mb::DeleteNetwork{})));
    BOOST_TEST(!mb::is_command(mb::type_of(mb::Response{})));
    BOOST_TEST(!mb::is_command(mb::type_of(mb::ScrubDone{})));
}

// Pins the byte layout documented in mailbox.hpp, so a refactor of the
// encoder cannot silently change the wire protocol.
BOOST_AUTO_TEST_CASE(wire_layouts_are_fixed, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((mb::encode_body(mb::DetachDevice{.vm_id = vm_b,
                                                 .device = nic,
                                                 .timeout_s = timeout_s,
                                                 .policy = mb::DetachPolicy::destroy_vm}) ==
                bytes_of(7, 0, 0, 0, 0, 0, 0, 0,  // vm_id
                         2, 1, 0x02, 0x01,        // slot, nic_vf, function 0x0102
                         30, 0,                   // timeout_s
                         2, 0)));                 // destroy_vm, rsvd
    BOOST_TEST((mb::encode_body(ok_response()) == bytes_of(9, 0, 0, 0, 0, 0, 0, 0,  // in_reply_to
                                                           0x10, 0x00,              // attach_device
                                                           1, 0)));                 // accepted
    BOOST_TEST((mb::encode_body(mb::HostFault{
                    .code = mb::FaultCode::device_lost, .slot = fault_slot, .detail = 1}) ==
                bytes_of(4, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0)));
    BOOST_TEST((mb::encode_body(mb::CreateNetwork{.vni = vni}) == bytes_of(0xEF, 0xCD, 0xAB, 0)));
    BOOST_TEST((mb::encode_body(nic_attach()) == bytes_of(0x44, 0x44, 0x33, 0x33, 0x22, 0x22, 0x11,
                                                          0x11,                 // vm_id
                                                          2, 1, 0x02, 0x01,     // nic_vf 0x0102
                                                          0xEF, 0xCD, 0xAB, 0,  // vni
                                                          0x10, 0, 0, 0, 0, 0, 0, 0,  // nic_id
                                                          0x02, 0, 0, 0, 0, 0x10,     // mac
                                                          0, 0)));                    // rsvd
}

// A NIC attach carries its VPC, NIC ID and MAC (protocol v3), so helm can
// configure oar-net from the signed command alone; a GPU attach carries none.
BOOST_AUTO_TEST_CASE(nic_attach_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto no_vni = nic_attach();
    no_vni.vni = 0;
    BOOST_TEST((decode_error(mb::Type::attach_device, mb::encode_body(no_vni)) ==
                BodyError::invalid_field));
    auto wide_vni = nic_attach();
    wide_vni.vni = mb::max_vni + 1;
    BOOST_TEST((decode_error(mb::Type::attach_device, mb::encode_body(wide_vni)) ==
                BodyError::invalid_field));
    auto no_nic_id = nic_attach();
    no_nic_id.nic_id = 0;
    BOOST_TEST((decode_error(mb::Type::attach_device, mb::encode_body(no_nic_id)) ==
                BodyError::invalid_field));
    expect_invalid(nic_attach(), attach_mac, multicast_mac);
    expect_invalid(nic_attach(), attach_mac, vendor_mac);
    expect_invalid(nic_attach(), attach_rsvd, nonzero);
    expect_invalid(nic_attach(), attach_rsvd + 1, nonzero);

    const mb::AttachDevice gpu_attach{.vm_id = vm_a, .device = gpu};
    expect_invalid(gpu_attach, attach_vni, nonzero);
    expect_invalid(gpu_attach, attach_nic_id, nonzero);
    expect_invalid(gpu_attach, attach_mac, std::byte{0x02});
}

BOOST_AUTO_TEST_CASE(wrong_lengths_are_rejected, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto& body : every_body()) {
        const auto type = mb::type_of(body);
        auto bytes = mb::encode_body(body);
        if (type == mb::Type::response) {
            continue;  // variable length: covered below
        }
        auto longer = bytes;
        longer.push_back(zero);
        BOOST_TEST((decode_error(type, longer) == BodyError::wrong_length));
        if (!bytes.empty()) {
            bytes.pop_back();
            BOOST_TEST((decode_error(type, bytes) == BodyError::wrong_length));
        }
    }
    auto short_response = mb::encode_body(ok_response());
    short_response.pop_back();
    BOOST_TEST((decode_error(mb::Type::response, short_response) == BodyError::wrong_length));
}

BOOST_AUTO_TEST_CASE(zero_identifiers_are_rejected,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::vector<mb::Body> bodies = {
        mb::VmStatus{},
        mb::AttachDevice{.device = nic, .vni = vni, .nic_id = nic_id, .mac = guest_mac},
        mb::DetachDevice{.device = nic, .timeout_s = timeout_s},
        mb::CreateVolume{.owner_vm = vm_a, .size_gib = volume_gib},
        mb::CreateVolume{.volume_id = volume, .size_gib = volume_gib},
        mb::DeleteVolume{},
        mb::AttachVolume{.vm_id = vm_a, .device = blk},
        mb::AttachVolume{.volume_id = volume, .device = blk},
        mb::DetachVolume{.vm_id = vm_a, .device = blk, .timeout_s = timeout_s},
        mb::RewrapVolume{.from_vm = vm_a, .to_vm = vm_b},
        mb::RewrapVolume{.volume_id = volume, .to_vm = vm_b},
        mb::RewrapVolume{.volume_id = volume, .from_vm = vm_a},
        mb::CreateNetwork{},
        mb::DeleteNetwork{},
        mb::VmExited{},
        mb::DeviceReleased{.device = nic},
    };
    for (const auto& body : bodies) {
        BOOST_TEST(
            (decode_error(mb::type_of(body), mb::encode_body(body)) == BodyError::invalid_field));
    }
}

BOOST_AUTO_TEST_CASE(field_ranges_are_enforced, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto rejects = [](const mb::Body& body) {
        BOOST_TEST(
            (decode_error(mb::type_of(body), mb::encode_body(body)) == BodyError::invalid_field));
    };
    rejects(mb::CreateVolume{.volume_id = volume, .owner_vm = vm_a, .size_gib = 0});
    rejects(mb::CreateVolume{
        .volume_id = volume, .owner_vm = vm_a, .size_gib = mb::max_volume_gib + 1});
    rejects(mb::CreateNetwork{.vni = mb::max_vni + 1});
    rejects(mb::RewrapVolume{.volume_id = volume, .from_vm = vm_a, .to_vm = vm_a});
    rejects(mb::DetachDevice{.vm_id = vm_a, .device = nic, .timeout_s = 0});
    rejects(mb::DetachVolume{.volume_id = volume,
                             .vm_id = vm_a,
                             .device = blk,
                             .timeout_s = mb::max_detach_timeout_s + 1});
}

// An image volume (oar-blk Requirement 8) is the 20-byte disk body plus
// its image source; the extra fields are checked like any other.
BOOST_AUTO_TEST_CASE(image_volume_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto bytes = mb::encode_body(image_volume());
    BOOST_REQUIRE(bytes.size() == image_volume_body_len);
    const auto plain = mb::encode_body(
        mb::CreateVolume{.volume_id = volume, .owner_vm = vm_a, .size_gib = volume_gib});
    BOOST_TEST(std::ranges::equal(std::span(bytes).first(plain.size()), plain));
    BOOST_TEST((bytes[image_store_offset] == std::byte{image_store}));
    BOOST_TEST((bytes[image_store_offset + 1] == zero));
    BOOST_TEST((bytes[image_store_offset + 2] == zero));
    BOOST_TEST((bytes[image_store_offset + 3] == zero));
    BOOST_TEST((bytes[image_name_offset] == std::byte{0x01}));
    BOOST_TEST((bytes[image_name_offset + 1] == std::byte{0x5A}));

    expect_invalid(image_volume(), image_store_offset, zero);  // store 0 in the long shape
    expect_invalid(image_volume(), image_store_offset + 2, nonzero);
    expect_invalid(image_volume(), image_store_offset + 3, nonzero);
    auto no_name = bytes;
    std::fill(no_name.begin() + image_name_offset, no_name.end(), zero);
    BOOST_TEST((decode_error(mb::Type::create_volume, no_name) == BodyError::invalid_field));
    // The disk-volume range rules still apply to the long shape.
    auto no_size = image_volume();
    no_size.size_gib = 0;
    BOOST_TEST((decode_error(mb::Type::create_volume, mb::encode_body(no_size)) ==
                BodyError::invalid_field));
}

// Storage functions only move with their volume (and its key); GPU scrub
// reports only name GPU functions.
BOOST_AUTO_TEST_CASE(device_types_match_the_command,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto rejects = [](const mb::Body& body) {
        BOOST_TEST(
            (decode_error(mb::type_of(body), mb::encode_body(body)) == BodyError::invalid_field));
    };
    auto blk_attach = nic_attach();
    blk_attach.device = blk;
    rejects(blk_attach);
    rejects(mb::AttachDevice{.vm_id = vm_a, .device = blk});
    rejects(mb::DetachDevice{.vm_id = vm_a, .device = blk, .timeout_s = timeout_s});
    rejects(mb::AttachVolume{.volume_id = volume, .vm_id = vm_a, .device = nic});
    rejects(mb::DetachVolume{.volume_id = volume, .vm_id = vm_a, .device = gpu, .timeout_s = 1});
    rejects(mb::ScrubDone{.device = nic});

    expect_invalid(nic_attach(), after_vm_id + device_type_in_ref, zero);
    expect_invalid(nic_attach(), after_vm_id + device_type_in_ref, bad_device_type);
    expect_invalid(mb::DeviceReleased{.vm_id = vm_a, .device = nic},
                   after_vm_id + device_type_in_ref, bad_device_type);
}

BOOST_AUTO_TEST_CASE(policy_timeout_and_reserved_bytes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const mb::DetachDevice dd{.vm_id = vm_a, .device = nic, .timeout_s = timeout_s};
    const std::size_t tail = after_vm_id;  // the *_in_tail offsets count from the device ref
    expect_invalid(dd, tail + policy_in_tail, zero);
    expect_invalid(dd, tail + policy_in_tail, bad_policy);
    expect_invalid(dd, tail + rsvd_in_tail, nonzero);

    const mb::DetachVolume dv{
        .volume_id = volume, .vm_id = vm_a, .device = blk, .timeout_s = timeout_s};
    const std::size_t vtail = after_two_ids;
    expect_invalid(dv, vtail + policy_in_tail, bad_policy);
    expect_invalid(dv, vtail + rsvd_in_tail, nonzero);
    auto bytes = mb::encode_body(dv);
    bytes[vtail + timeout_in_tail] = std::byte{too_long_timeout};
    bytes[vtail + timeout_in_tail + 1] = std::byte{too_long_timeout_hi};
    BOOST_TEST((decode_error(mb::Type::detach_volume, bytes) == BodyError::invalid_field));
}

BOOST_AUTO_TEST_CASE(event_enums_and_reserved_bytes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::size_t exit_reason = 12;
    constexpr std::size_t exit_rsvd = 13;
    const mb::VmExited exited{.vm_id = vm_a};
    expect_invalid(exited, exit_reason, zero);
    expect_invalid(exited, exit_reason, std::byte{4});
    expect_invalid(exited, exit_rsvd, nonzero);

    constexpr std::size_t reset = 12;
    constexpr std::size_t reset_rsvd = 13;
    const mb::DeviceReleased released{.vm_id = vm_a, .device = nic};
    expect_invalid(released, reset, std::byte{2});
    expect_invalid(released, reset_rsvd, nonzero);

    constexpr std::size_t fault_code_lo = 0;
    constexpr std::size_t fault_rsvd = 3;
    const mb::HostFault fault{};
    expect_invalid(fault, fault_code_lo, zero);
    expect_invalid(fault, fault_code_lo, std::byte{6});
    expect_invalid(fault, fault_rsvd, nonzero);

    constexpr std::size_t scrub_result = 4;
    constexpr std::size_t scrub_rsvd = 5;
    const mb::ScrubDone scrub{.device = gpu};
    expect_invalid(scrub, scrub_result, std::byte{2});
    expect_invalid(scrub, scrub_rsvd, nonzero);
}

BOOST_AUTO_TEST_CASE(response_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::size_t command_lo = 8;
    constexpr std::size_t command_hi = 9;
    constexpr std::size_t status_lo = 10;

    // The command must be a known command type, not a response or event.
    expect_invalid(ok_response(), command_lo, std::byte{0xEE});
    auto resp = mb::encode_body(ok_response());
    resp[command_lo] = zero;
    resp[command_hi] = std::byte{0x01};  // 0x0100 = response
    BOOST_TEST((decode_error(mb::Type::response, resp) == BodyError::invalid_field));
    resp[command_hi] = std::byte{0x02};  // 0x0200 = vm_exited
    BOOST_TEST((decode_error(mb::Type::response, resp) == BodyError::invalid_field));

    expect_invalid(ok_response(), status_lo, std::byte{14});

    // A reply to a command that can never be built yet is still a reply.
    auto reserved = ok_response();
    reserved.command = mb::Type::gpu_vf_config;
    reserved.status = mb::Status::unsupported;
    BOOST_TEST(mb::decode_body(message(reserved)).has_value());

    // Payloads only on ok replies to the query commands.
    auto payload_on_error = ok_response();
    payload_on_error.command = mb::Type::vm_status;
    payload_on_error.status = mb::Status::unknown_vm;
    payload_on_error.payload_len = 1;
    BOOST_TEST((decode_error(mb::Type::response, mb::encode_body(payload_on_error)) ==
                BodyError::invalid_field));
    auto payload_on_attach = ok_response();
    payload_on_attach.status = mb::Status::ok;
    payload_on_attach.payload_len = 1;
    BOOST_TEST((decode_error(mb::Type::response, mb::encode_body(payload_on_attach)) ==
                BodyError::invalid_field));
}

BOOST_AUTO_TEST_CASE(gpu_vf_config_is_reserved, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((decode_error(mb::Type::gpu_vf_config, {}) == BodyError::reserved_type));
    BOOST_TEST(
        (decode_error(mb::Type::gpu_vf_config, bytes_of(1, 2, 3)) == BodyError::reserved_type));
    BOOST_TEST(mb::to_string(BodyError::reserved_type) == std::string_view{"reserved_type"});
}

BOOST_AUTO_TEST_CASE(hand_built_message_with_unknown_type,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::uint16_t not_a_type = 0x7777;
    mb::Message msg;
    msg.header.type = static_cast<mb::Type>(not_a_type);
    BOOST_TEST((mb::decode_body(msg).error() == BodyError::wrong_type));
}
