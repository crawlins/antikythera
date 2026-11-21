// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirements 5 and 7: OarLink message
// bodies (helm/oar_protocol.hpp), strict both ways.

#define BOOST_TEST_MODULE oar_protocol_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "helm/oar_protocol.hpp"
#include "proto/group_policy.hpp"
#include "proto/map_update.hpp"
#include "proto/report.hpp"
#include "test_support.hpp"

namespace oar = ak::helm::oar;
using ak::helm::CleaningAction;
using ak::helm::FunctionType;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using oar::BodyError;
using oar::Status;

namespace {

constexpr oar::FunctionNumber sample_fn = 0x0102;
constexpr ak::helm::VmId sample_vm = 0x1122'3344'5566'7788;
constexpr oar::NicId sample_nic = 0x0A0B'0C0D'0E0F'1011;
constexpr std::uint32_t sample_vni = 0x00AB'CDEF;
constexpr ak::helm::VolumeId sample_volume = 0x99;
constexpr oar::Mac local_mac{std::byte{0x02}, std::byte{0x00}, std::byte{0x5E},
                             std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
constexpr oar::Mac global_mac{std::byte{0x00}, std::byte{0x11}, std::byte{0x22},
                              std::byte{0x33}, std::byte{0x44}, std::byte{0x55}};
constexpr oar::Mac multicast_mac{std::byte{0x03}, std::byte{0x00}, std::byte{0x00},
                                 std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
constexpr std::uint32_t wide_vni = 0x0100'0000;
constexpr std::size_t nic_body_size = oar::prepare_head_size + oar::nic_config_size;
constexpr std::size_t blk_body_size = oar::prepare_head_size + oar::blk_config_size;
constexpr std::size_t type_offset = 2;
constexpr std::size_t reserved8_offset = 3;
constexpr std::size_t reserved32_offset = 4;
constexpr std::size_t nic_reserved_offset = nic_body_size - 1;
constexpr std::uint8_t bad_type = 9;
constexpr std::uint8_t bad_action = 4;
constexpr std::uint8_t bad_status = 7;
constexpr std::uint8_t key_fill = 0xA5;
constexpr std::uint32_t small_total = 100;
constexpr std::uint32_t mid_offset = 40;
constexpr std::size_t fn_count = 3;
constexpr std::uint64_t sample_sectors = 0x20'0000;  // 1 GiB
constexpr std::size_t wrapped_size = 95;             // helm's format-1 volume blob
constexpr std::uint8_t wrapped_fill = 0x3C;
constexpr std::size_t key_len_offset = 28;
constexpr std::size_t create_reserved_offset = 30;
constexpr std::size_t block_size_offset = 24;
constexpr std::size_t rewrap_key_len_offset = 16;
constexpr std::size_t rewrap_reserved_offset = 20;

auto nic_request() -> oar::PrepareFunction {
    return {.fn = sample_fn,
            .type = FunctionType::nic_vf,
            .vm_id = sample_vm,
            .config = oar::NicConfig{.nic_id = sample_nic, .vni = sample_vni, .mac = local_mac}};
}

auto net_inventory() -> oar::Inventory {
    oar::Inventory inv{.role = oar::Role::net, .vtep = {}, .functions = {}};
    inv.vtep.back() = std::byte{1};
    for (std::size_t i = 0; i < fn_count; ++i) {
        inv.functions.push_back(
            {.fn = static_cast<oar::FunctionNumber>(i * 2), .type = FunctionType::nic_vf});
    }
    return inv;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(oar_protocol, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(map_frame_limit_matches_proto) {
    BOOST_TEST(oar::max_map_frame == ak::proto::max_map_update_size);
    BOOST_TEST(oar::max_map_chunk + oar::map_chunk_head_size + ak::helm::mctp::vendor_header_size ==
               ak::helm::mctp::max_message_size);
}

BOOST_AUTO_TEST_CASE(prepare_nic_layout_and_round_trip) {
    auto body = oar::encode_prepare_function(nic_request());
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == nic_body_size);
    // fn LE, type, then vm_id LE at 8.
    BOOST_TEST(std::to_integer<int>((*body)[0]) == 0x02);
    BOOST_TEST(std::to_integer<int>((*body)[1]) == 0x01);
    BOOST_TEST(std::to_integer<int>((*body)[type_offset]) == 1);
    BOOST_TEST(std::to_integer<int>((*body)[8]) == 0x88);
    auto back = oar::decode_prepare_function(*body);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == nic_request()));
}

BOOST_AUTO_TEST_CASE(prepare_blk_and_gpu_round_trip) {
    const oar::PrepareFunction blk{.fn = 1,
                                   .type = FunctionType::blk_fn,
                                   .vm_id = sample_vm,
                                   .config = oar::BlkConfig{.volume_id = sample_volume}};
    auto body = oar::encode_prepare_function(blk);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == blk_body_size);
    BOOST_TEST((oar::decode_prepare_function(*body).value() == blk));

    const oar::PrepareFunction gpu{
        .fn = 1, .type = FunctionType::gpu_vf, .vm_id = sample_vm, .config = std::monostate{}};
    body = oar::encode_prepare_function(gpu);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::prepare_head_size);
    BOOST_TEST((oar::decode_prepare_function(*body).value() == gpu));
}

BOOST_AUTO_TEST_CASE(prepare_encode_rejects_invalid) {
    auto p = nic_request();
    p.vm_id = 0;
    BOOST_TEST((oar::encode_prepare_function(p).error() == BodyError::zero_id));
    p = nic_request();
    p.config = oar::BlkConfig{.volume_id = sample_volume};
    BOOST_TEST((oar::encode_prepare_function(p).error() == BodyError::type_mismatch));
    p = nic_request();
    std::get<oar::NicConfig>(p.config).nic_id = 0;
    BOOST_TEST((oar::encode_prepare_function(p).error() == BodyError::zero_id));
    for (const std::uint32_t vni : {std::uint32_t{0}, wide_vni}) {
        p = nic_request();
        std::get<oar::NicConfig>(p.config).vni = vni;
        BOOST_TEST((oar::encode_prepare_function(p).error() == BodyError::bad_vni));
    }
    for (const auto& mac : {global_mac, multicast_mac}) {
        p = nic_request();
        std::get<oar::NicConfig>(p.config).mac = mac;
        BOOST_TEST((oar::encode_prepare_function(p).error() == BodyError::bad_mac));
    }
    const oar::PrepareFunction blk{.fn = 1,
                                   .type = FunctionType::blk_fn,
                                   .vm_id = sample_vm,
                                   .config = oar::BlkConfig{.volume_id = 0}};
    BOOST_TEST((oar::encode_prepare_function(blk).error() == BodyError::zero_id));
}

BOOST_AUTO_TEST_CASE(prepare_decode_rejects_malformed) {
    const auto good = oar::encode_prepare_function(nic_request()).value();

    auto b = good;
    b.pop_back();
    BOOST_TEST((oar::decode_prepare_function(b).error() == BodyError::truncated));
    b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((oar::decode_prepare_function(b).error() == BodyError::trailing_bytes));
    BOOST_TEST(
        (oar::decode_prepare_function(std::span{good}.first(oar::prepare_head_size - 1)).error() ==
         BodyError::truncated));

    for (const std::size_t off : {reserved8_offset, reserved32_offset, nic_reserved_offset}) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((oar::decode_prepare_function(b).error() == BodyError::reserved_not_zero));
    }
    b = good;
    b[type_offset] = std::byte{bad_type};
    BOOST_TEST((oar::decode_prepare_function(b).error() == BodyError::unknown_enum));
    // A blk type over a NIC-sized body has the wrong length for its type.
    b = good;
    b[type_offset] = std::byte{static_cast<std::uint8_t>(FunctionType::blk_fn)};
    BOOST_TEST((oar::decode_prepare_function(b).error() == BodyError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(clean_function_round_trip_and_rejects) {
    const oar::CleanFunction c{.fn = sample_fn, .action = CleaningAction::drop_volume_key};
    auto body = oar::encode_clean_function(c);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::clean_function_size);
    BOOST_TEST((oar::decode_clean_function(*body).value() == c));

    BOOST_TEST((oar::decode_clean_function(bytes_of(0, 0, bad_action, 0)).error() ==
                BodyError::unknown_enum));
    BOOST_TEST(
        (oar::decode_clean_function(bytes_of(0, 0, 0, 1)).error() == BodyError::reserved_not_zero));
    BOOST_TEST((oar::decode_clean_function(bytes_of(0, 0, 0)).error() == BodyError::truncated));
    BOOST_TEST(
        (oar::encode_clean_function({.fn = 0, .action = static_cast<CleaningAction>(bad_action)})
             .error() == BodyError::unknown_enum));
}

BOOST_AUTO_TEST_CASE(deliver_key_round_trip_views_key) {
    std::array<std::byte, ak::helm::volume_key_size> key{};
    key.fill(std::byte{key_fill});
    auto body = oar::encode_deliver_key({.fn = sample_fn, .volume_id = sample_volume, .key = key});
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::deliver_key_size);
    BOOST_TEST(body->capacity() == oar::deliver_key_size);  // no reallocation copies
    auto back = oar::decode_deliver_key(*body);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->fn == sample_fn);
    BOOST_TEST(back->volume_id == sample_volume);
    BOOST_TEST(std::ranges::equal(back->key, key));
    BOOST_TEST(back->key.data() == body->data() + (oar::deliver_key_size - key.size()));

    BOOST_TEST((oar::encode_deliver_key({.fn = 0, .volume_id = 0, .key = key}).error() ==
                BodyError::zero_id));
    auto b = *body;
    b[2] = std::byte{1};
    BOOST_TEST((oar::decode_deliver_key(b).error() == BodyError::reserved_not_zero));
    b.pop_back();
    BOOST_TEST((oar::decode_deliver_key(b).error() == BodyError::truncated));
}

BOOST_AUTO_TEST_CASE(drop_key_round_trip_and_rejects) {
    const oar::DropKey d{.fn = sample_fn, .volume_id = sample_volume};
    auto body = oar::encode_drop_key(d);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST((oar::decode_drop_key(*body).value() == d));
    auto b = *body;
    std::ranges::fill(std::span{b}.subspan(8), std::byte{0});
    BOOST_TEST((oar::decode_drop_key(b).error() == BodyError::zero_id));
    b = *body;
    b[7] = std::byte{1};
    BOOST_TEST((oar::decode_drop_key(b).error() == BodyError::reserved_not_zero));
    b = *body;
    b.push_back(std::byte{0});
    BOOST_TEST((oar::decode_drop_key(b).error() == BodyError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(create_volume_layout_and_round_trip) {
    const std::vector<std::byte> wrapped(wrapped_size, std::byte{wrapped_fill});
    const oar::CreateVolume c{.volume_id = sample_volume,
                              .owner_vm = sample_vm,
                              .capacity_sectors = sample_sectors,
                              .block_size = oar::sector_size,
                              .wrapped_key = wrapped};
    auto body = oar::encode_create_volume(c);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::create_volume_head_size + wrapped_size);
    BOOST_TEST(std::to_integer<std::size_t>((*body)[key_len_offset]) == wrapped_size);
    auto back = oar::decode_create_volume(*body);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->volume_id == sample_volume);
    BOOST_TEST(back->owner_vm == sample_vm);
    BOOST_TEST(back->capacity_sectors == sample_sectors);
    BOOST_TEST(back->block_size == oar::sector_size);
    BOOST_TEST(std::ranges::equal(back->wrapped_key, wrapped));
    BOOST_TEST(back->wrapped_key.data() == body->data() + oar::create_volume_head_size);

    auto b = *body;
    // Offset 30 is the image store: set, the next 32 bytes are an image name
    // and the key that follows is too short for its length.
    b[create_reserved_offset] = std::byte{1};
    BOOST_TEST((oar::decode_create_volume(b).error() == BodyError::bad_key_length));
    b = *body;
    b.push_back(std::byte{0});
    BOOST_TEST((oar::decode_create_volume(b).error() == BodyError::bad_key_length));
    b = *body;
    b.resize(oar::create_volume_head_size - 1);
    BOOST_TEST((oar::decode_create_volume(b).error() == BodyError::truncated));
    b = *body;
    b[block_size_offset + 1] = std::byte{0x04};  // 1024 + 0 = not 512/4096
    BOOST_TEST((oar::decode_create_volume(b).error() == BodyError::bad_geometry));
}

BOOST_AUTO_TEST_CASE(create_volume_rules) {
    const std::vector<std::byte> wrapped(wrapped_size, std::byte{wrapped_fill});
    const std::vector<std::byte> too_long(oar::max_wrapped_volume_key + 1, std::byte{1});
    const oar::CreateVolume good{.volume_id = sample_volume,
                                 .owner_vm = sample_vm,
                                 .capacity_sectors = sample_sectors,
                                 .block_size = 4096,
                                 .wrapped_key = wrapped};
    BOOST_TEST(oar::encode_create_volume(good).has_value());
    auto c = good;
    c.owner_vm = 0;
    BOOST_TEST((oar::encode_create_volume(c).error() == BodyError::zero_id));
    c = good;
    c.capacity_sectors = 0;
    BOOST_TEST((oar::encode_create_volume(c).error() == BodyError::bad_geometry));
    c = good;
    c.capacity_sectors = sample_sectors + 1;  // not whole 4 KiB blocks
    BOOST_TEST((oar::encode_create_volume(c).error() == BodyError::bad_geometry));
    c = good;
    c.capacity_sectors = oar::max_capacity_sectors + 8;
    BOOST_TEST((oar::encode_create_volume(c).error() == BodyError::bad_geometry));
    c = good;
    c.wrapped_key = {};
    BOOST_TEST((oar::encode_create_volume(c).error() == BodyError::bad_key_length));
    c.wrapped_key = too_long;
    BOOST_TEST((oar::encode_create_volume(c).error() == BodyError::bad_key_length));
}

BOOST_AUTO_TEST_CASE(create_image_volume_layout_and_rules) {
    oar::ImageName name{};
    for (std::size_t i = 0; i < name.size(); ++i) {
        name[i] = static_cast<std::byte>(0xA0 + i);
    }
    // A plain image: no key, the name right after the head.
    const oar::CreateVolume c{.volume_id = sample_volume,
                              .owner_vm = sample_vm,
                              .capacity_sectors = sample_sectors,
                              .block_size = oar::sector_size,
                              .wrapped_key = {},
                              .image_store = 3,
                              .image_name = name};
    auto body = oar::encode_create_volume(c);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::create_volume_head_size + oar::image_name_size);
    BOOST_TEST(std::to_integer<int>((*body)[create_reserved_offset]) == 3);
    BOOST_TEST(std::to_integer<int>((*body)[key_len_offset]) == 0);
    BOOST_TEST(std::ranges::equal(std::span{*body}.subspan(oar::create_volume_head_size), name));
    auto back = oar::decode_create_volume(*body);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->image_store == 3);
    BOOST_TEST((back->image_name == name));
    BOOST_TEST(back->wrapped_key.empty());

    // An encrypted image's volume carries its wrapped image key after the name.
    const std::vector<std::byte> wrapped(wrapped_size, std::byte{wrapped_fill});
    auto e = c;
    e.wrapped_key = wrapped;
    body = oar::encode_create_volume(e);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::create_volume_head_size + oar::image_name_size + wrapped_size);
    back = oar::decode_create_volume(*body);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(std::ranges::equal(back->wrapped_key, wrapped));
    BOOST_TEST((back->image_name == name));

    auto b = oar::encode_create_volume(c).value();
    b.push_back(std::byte{0});  // nothing may follow a plain image's name
    BOOST_TEST((oar::decode_create_volume(b).error() == BodyError::bad_key_length));
    b = oar::encode_create_volume(c).value();
    b.pop_back();
    BOOST_TEST((oar::decode_create_volume(b).error() == BodyError::truncated));
    b = oar::encode_create_volume(c).value();
    std::ranges::fill(std::span{b}.subspan(oar::create_volume_head_size), std::byte{0});
    BOOST_TEST((oar::decode_create_volume(b).error() == BodyError::bad_image));

    auto bad = c;
    bad.image_name = {};
    BOOST_TEST((oar::encode_create_volume(bad).error() == BodyError::bad_image));
    bad = c;
    bad.image_store = 0;  // a disk volume names no image
    BOOST_TEST((oar::encode_create_volume(bad).error() == BodyError::bad_image));
}

BOOST_AUTO_TEST_CASE(delete_and_rewrap_volume) {
    const oar::DeleteVolume d{.volume_id = sample_volume};
    auto body = oar::encode_delete_volume(d);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::delete_volume_size);
    BOOST_TEST((oar::decode_delete_volume(*body).value() == d));
    BOOST_TEST((oar::encode_delete_volume({.volume_id = 0}).error() == BodyError::zero_id));
    BOOST_TEST((oar::decode_delete_volume(bytes_of(0, 0, 0, 0, 0, 0, 0, 0)).error() ==
                BodyError::zero_id));
    auto b = *body;
    b.push_back(std::byte{0});
    BOOST_TEST((oar::decode_delete_volume(b).error() == BodyError::trailing_bytes));

    const std::vector<std::byte> wrapped(wrapped_size, std::byte{wrapped_fill});
    auto rw = oar::encode_rewrap_volume(
        {.volume_id = sample_volume, .owner_vm = sample_vm, .wrapped_key = wrapped});
    BOOST_REQUIRE(rw.has_value());
    BOOST_TEST(rw->size() == oar::rewrap_volume_head_size + wrapped_size);
    BOOST_TEST(std::to_integer<std::size_t>((*rw)[rewrap_key_len_offset]) == wrapped_size);
    auto back = oar::decode_rewrap_volume(*rw);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->volume_id == sample_volume);
    BOOST_TEST(back->owner_vm == sample_vm);
    BOOST_TEST(std::ranges::equal(back->wrapped_key, wrapped));
    b = *rw;
    b[rewrap_reserved_offset] = std::byte{1};
    BOOST_TEST((oar::decode_rewrap_volume(b).error() == BodyError::reserved_not_zero));
    b = *rw;
    b.pop_back();
    BOOST_TEST((oar::decode_rewrap_volume(b).error() == BodyError::bad_key_length));
    BOOST_TEST((oar::encode_rewrap_volume(
                    {.volume_id = sample_volume, .owner_vm = 0, .wrapped_key = wrapped})
                    .error() == BodyError::zero_id));
}

BOOST_AUTO_TEST_CASE(tunnel_keys_round_trip_and_rejects) {
    std::array<std::byte, oar::tunnel_key_size> priv{};
    priv.fill(std::byte{key_fill});
    auto body = oar::encode_set_tunnel_key({.private_key = priv});
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::set_tunnel_key_size);
    BOOST_TEST(body->capacity() == oar::set_tunnel_key_size);  // no stray copies
    auto key = oar::decode_set_tunnel_key(*body);
    BOOST_REQUIRE(key.has_value());
    BOOST_TEST(key->private_key.data() == body->data());  // a view, not a copy
    const std::array<std::byte, oar::tunnel_key_size> zero{};
    BOOST_TEST((oar::encode_set_tunnel_key({.private_key = zero}).error() == BodyError::zero_key));
    BOOST_TEST((oar::decode_set_tunnel_key(zero).error() == BodyError::zero_key));
    auto b = *body;
    b.push_back(std::byte{0});
    BOOST_TEST((oar::decode_set_tunnel_key(b).error() == BodyError::trailing_bytes));

    oar::Vtep vtep{};
    vtep[0] = std::byte{0xfd};
    vtep.back() = std::byte{2};
    std::array<std::byte, oar::tunnel_key_size> pub{};
    pub.fill(std::byte{0x42});
    std::array<std::byte, oar::tunnel_key_size> psk{};  // none
    auto peer = oar::encode_set_tunnel_peer({.vtep = vtep, .public_key = pub, .psk = psk});
    BOOST_REQUIRE(peer.has_value());
    BOOST_TEST(peer->size() == oar::set_tunnel_peer_size);
    BOOST_TEST(peer->capacity() == oar::set_tunnel_peer_size);
    BOOST_TEST(std::ranges::equal(std::span{*peer}.first(oar::vtep_size), vtep));
    auto back = oar::decode_set_tunnel_peer(*peer);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->vtep == vtep));
    BOOST_TEST(std::ranges::equal(back->public_key, pub));
    BOOST_TEST(std::ranges::equal(back->psk, psk));
    BOOST_TEST((oar::encode_set_tunnel_peer({.vtep = {}, .public_key = pub, .psk = psk}).error() ==
                BodyError::bad_vtep));
    BOOST_TEST(
        (oar::encode_set_tunnel_peer({.vtep = vtep, .public_key = zero, .psk = psk}).error() ==
         BodyError::zero_key));
    b = *peer;
    std::ranges::fill(std::span{b}.subspan(oar::vtep_size, oar::tunnel_key_size), std::byte{0});
    BOOST_TEST((oar::decode_set_tunnel_peer(b).error() == BodyError::zero_key));
    b = *peer;
    std::ranges::fill(std::span{b}.first(oar::vtep_size), std::byte{0});
    BOOST_TEST((oar::decode_set_tunnel_peer(b).error() == BodyError::bad_vtep));
    b.pop_back();
    BOOST_TEST((oar::decode_set_tunnel_peer(b).error() == BodyError::truncated));

    auto rm = oar::encode_remove_tunnel_peer({.vtep = vtep});
    BOOST_REQUIRE(rm.has_value());
    BOOST_TEST(
        (oar::decode_remove_tunnel_peer(*rm).value() == oar::RemoveTunnelPeer{.vtep = vtep}));
    BOOST_TEST((oar::encode_remove_tunnel_peer({}).error() == BodyError::bad_vtep));
    BOOST_TEST((oar::decode_remove_tunnel_peer(std::span{zero}.first(oar::vtep_size)).error() ==
                BodyError::bad_vtep));
}

BOOST_AUTO_TEST_CASE(map_chunk_bounds) {
    const std::vector<std::byte> data(mid_offset, std::byte{1});
    auto body = oar::encode_map_chunk({.total = small_total, .offset = 0, .chunk = data});
    BOOST_REQUIRE(body.has_value());
    auto back = oar::decode_map_chunk(*body);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->total == small_total);
    BOOST_TEST(back->offset == 0U);
    BOOST_TEST(std::ranges::equal(back->chunk, data));

    const auto bad = [](std::uint32_t total, std::uint32_t offset, std::size_t len) {
        const std::vector<std::byte> chunk(len, std::byte{0});
        return oar::encode_map_chunk({.total = total, .offset = offset, .chunk = chunk}).error() ==
               BodyError::bad_chunk;
    };
    BOOST_TEST(bad(0, 0, 1));                                                // empty frame
    BOOST_TEST(bad(small_total, 0, 0));                                      // empty chunk
    BOOST_TEST(bad(small_total, small_total, 1));                            // offset past the end
    BOOST_TEST(bad(small_total, small_total - mid_offset + 1, mid_offset));  // overruns total
    BOOST_TEST(bad(oar::max_map_frame + 1, 0, 1));                           // frame too large
    BOOST_TEST(bad(oar::max_map_frame, 0, oar::max_map_chunk + 1));          // chunk too large
    BOOST_TEST(!bad(oar::max_map_frame, 0, oar::max_map_chunk));

    BOOST_TEST(
        (oar::decode_map_chunk(bytes_of(1, 0, 0, 0, 0, 0, 0, 0)).error() == BodyError::truncated));
}

BOOST_AUTO_TEST_CASE(empty_bodies) {
    BOOST_TEST(oar::decode_empty({}).has_value());
    BOOST_TEST((oar::decode_empty(bytes_of(0)).error() == BodyError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(response_heads) {
    auto ok = oar::encode_response(Status::ok, bytes_of(1, 2));
    BOOST_REQUIRE(ok.has_value());
    BOOST_TEST((*ok == bytes_of(0, 0, 1, 2)));
    auto view = oar::decode_response(*ok);
    BOOST_REQUIRE(view.has_value());
    BOOST_TEST((view->status == Status::ok));
    BOOST_TEST(view->body.size() == 2U);

    auto busy = oar::encode_response(Status::busy);
    BOOST_REQUIRE(busy.has_value());
    BOOST_TEST((oar::decode_response(*busy)->status == Status::busy));

    BOOST_TEST(
        (oar::encode_response(Status::busy, bytes_of(1)).error() == BodyError::status_with_body));
    BOOST_TEST((oar::decode_response(bytes_of(4, 0, 1)).error() == BodyError::status_with_body));
    BOOST_TEST((oar::decode_response(bytes_of(bad_status, 0)).error() == BodyError::unknown_enum));
    BOOST_TEST((oar::decode_response(bytes_of(0, 1)).error() == BodyError::reserved_not_zero));
    BOOST_TEST((oar::decode_response(bytes_of(0)).error() == BodyError::truncated));
}

BOOST_AUTO_TEST_CASE(inventory_round_trip) {
    const auto inv = net_inventory();
    auto body = oar::encode_inventory(inv);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::inventory_head_size + (fn_count * oar::inventory_entry_size));
    auto back = oar::decode_inventory(*body);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == inv));

    const oar::Inventory empty_blk{.role = oar::Role::blk, .vtep = {}, .functions = {}};
    BOOST_TEST(
        (oar::decode_inventory(oar::encode_inventory(empty_blk).value()).value() == empty_blk));
}

BOOST_AUTO_TEST_CASE(inventory_rules) {
    auto inv = net_inventory();
    inv.vtep = {};
    BOOST_TEST((oar::encode_inventory(inv).error() == BodyError::bad_vtep));
    inv = net_inventory();
    inv.role = oar::Role::blk;
    BOOST_TEST((oar::encode_inventory(inv).error() == BodyError::bad_vtep));
    inv.vtep = {};
    BOOST_TEST((oar::encode_inventory(inv).error() == BodyError::type_mismatch));
    inv = net_inventory();
    inv.functions[1].fn = inv.functions[0].fn;
    BOOST_TEST((oar::encode_inventory(inv).error() == BodyError::not_increasing));
    inv = net_inventory();
    inv.functions.resize(oar::max_inventory_entries + 1);
    BOOST_TEST((oar::encode_inventory(inv).error() == BodyError::too_many_entries));

    const oar::Inventory gpu{.role = oar::Role::gpu,
                             .vtep = {},
                             .functions = {{.fn = 0, .type = FunctionType::gpu_whole},
                                           {.fn = 1, .type = FunctionType::gpu_vf}}};
    BOOST_TEST(oar::encode_inventory(gpu).has_value());

    const auto good = oar::encode_inventory(net_inventory()).value();
    auto b = good;
    b.pop_back();
    BOOST_TEST((oar::decode_inventory(b).error() == BodyError::truncated));
    b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((oar::decode_inventory(b).error() == BodyError::trailing_bytes));
    b = good;
    b[1] = std::byte{1};
    BOOST_TEST((oar::decode_inventory(b).error() == BodyError::reserved_not_zero));
    b = good;
    b[0] = std::byte{0};
    BOOST_TEST((oar::decode_inventory(b).error() == BodyError::unknown_enum));
    b = good;
    b.back() = std::byte{1};  // last entry's reserved byte
    BOOST_TEST((oar::decode_inventory(b).error() == BodyError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(health_round_trip_and_rejects) {
    const oar::Health h{.state = oar::HealthState::degraded, .fault_code = 7, .uptime_seconds = 9};
    auto body = oar::encode_health(h);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST((oar::decode_health(*body).value() == h));
    BOOST_TEST(
        (oar::decode_health(bytes_of(3, 0, 0, 0, 0, 0, 0, 0)).error() == BodyError::unknown_enum));
    BOOST_TEST((oar::decode_health(bytes_of(0, 1, 0, 0, 0, 0, 0, 0)).error() ==
                BodyError::reserved_not_zero));
}

namespace {

auto usage(std::uint64_t nic, std::uint64_t attachment, bool detached = false) -> oar::UsageEntry {
    return {.nic_id = nic,
            .vni = 9,
            .detached = detached,
            .attachment = attachment,
            .frames = 1,
            .bytes = 2,
            .replicas_remote = 3,
            .replica_bytes_remote = 4,
            .replicas_local = 5,
            .replica_bytes_local = 6,
            .drop_policy = 7,
            .drop_rate = 8,
            .drop_fanout = 9};
}

}  // namespace

BOOST_AUTO_TEST_CASE(group_mirrors_match_proto) {
    BOOST_TEST(oar::group_policy_frame_size == ak::proto::group_policy_size);
    BOOST_TEST(oar::usage_entry_size == ak::proto::group_usage_entry_size);
    BOOST_TEST(oar::max_usage_entries == ak::proto::max_group_usage_entries);
    BOOST_TEST(oar::usage_detached == ak::proto::group_usage_detached);
    // A full page fits one message.
    BOOST_TEST(oar::response_head_size + oar::usage_head_size +
                   (oar::max_usage_page * oar::usage_entry_size) <=
               oar::max_body_size);
}

BOOST_AUTO_TEST_CASE(group_policy_frame_and_usage_request) {
    const std::vector<std::byte> frame(oar::group_policy_frame_size, std::byte{3});
    BOOST_TEST(oar::decode_group_policy_frame(oar::encode_group_policy_frame(frame).value())
                   .value()
                   .size() == frame.size());
    BOOST_TEST((oar::encode_group_policy_frame(std::span{frame}.first(5)).error() ==
                BodyError::truncated));
    BOOST_TEST((oar::decode_group_policy_frame(std::vector<std::byte>(129)).error() ==
                BodyError::trailing_bytes));
    BOOST_TEST(oar::decode_usage_request(oar::encode_usage_request(41).value()).value() == 41);
    BOOST_TEST(
        (oar::decode_usage_request(bytes_of(0, 0, 1, 0)).error() == BodyError::reserved_not_zero));
    BOOST_TEST((oar::decode_usage_request(bytes_of(0, 0)).error() == BodyError::truncated));
}

BOOST_AUTO_TEST_CASE(usage_page_round_trip_and_rules) {
    const oar::UsagePage page{.total = 5, .entries = {usage(1, 1), usage(2, 7, true)}};
    auto body = oar::encode_usage_page(page, 3);
    BOOST_REQUIRE(body.has_value());
    BOOST_TEST(body->size() == oar::usage_head_size + (2 * oar::usage_entry_size));
    BOOST_TEST((oar::decode_usage_page(*body, 3).value() == page));
    // The page must fit the cursor it answers.
    BOOST_TEST((oar::decode_usage_page(*body, 4).error() == BodyError::bad_chunk));
    BOOST_TEST((oar::encode_usage_page(page, 4).error() == BodyError::bad_chunk));
    BOOST_TEST(
        (oar::encode_usage_page({.total = 3, .entries = {}}, 0).error() == BodyError::bad_chunk));
    BOOST_TEST(oar::encode_usage_page({.total = 0, .entries = {}}, 0).has_value());

    auto bad = page;
    bad.entries[1].nic_id = 0;
    BOOST_TEST((oar::encode_usage_page(bad, 0).error() == BodyError::zero_id));
    bad = page;
    bad.entries[1].vni = 0;
    BOOST_TEST((oar::encode_usage_page(bad, 0).error() == BodyError::bad_vni));
    bad = page;
    std::swap(bad.entries[0], bad.entries[1]);
    BOOST_TEST((oar::encode_usage_page(bad, 0).error() == BodyError::not_increasing));
    bad = {.total = 100, .entries = std::vector<oar::UsageEntry>(41, usage(1, 1))};
    BOOST_TEST((oar::encode_usage_page(bad, 0).error() == BodyError::too_many_entries));

    auto b = *body;
    b[oar::usage_head_size + oar::usage_entry_size + 12] = std::byte{0x03};  // unknown flag
    BOOST_TEST((oar::decode_usage_page(b, 3).error() == BodyError::reserved_not_zero));
    b = *body;
    b[4] = std::byte{0};  // reserved head
    b[6] = std::byte{1};
    BOOST_TEST((oar::decode_usage_page(b, 3).error() == BodyError::reserved_not_zero));
    b = *body;
    b.pop_back();
    BOOST_TEST((oar::decode_usage_page(b, 3).error() == BodyError::truncated));
}

BOOST_AUTO_TEST_CASE(pager_pages_one_snapshot) {
    oar::UsagePager pager;
    int calls = 0;
    std::vector<oar::UsageEntry> meters;
    for (std::uint64_t n = 90; n >= 1; --n) {
        meters.push_back(usage(n, 1));
    }
    const auto snap = [&] {
        ++calls;
        return meters;
    };
    BOOST_TEST((pager.page(5, snap).error() == Status::bad_request));  // no snapshot yet
    auto p0 = pager.page(0, snap).value();
    BOOST_TEST(p0.total == 90);
    BOOST_TEST(p0.entries.size() == oar::max_usage_page);
    BOOST_TEST(p0.entries.front().nic_id == 1U);  // sorted
    auto p1 = pager.page(40, snap).value();
    auto p2 = pager.page(80, snap).value();
    BOOST_TEST(p1.entries.front().nic_id == 41U);
    BOOST_TEST(p2.entries.size() == 10U);
    BOOST_TEST(calls == 1);
    // After the last page the snapshot is closed.
    BOOST_TEST((pager.page(80, snap).error() == Status::bad_request));
    // An empty role answers one empty page.
    meters.clear();
    BOOST_TEST(pager.page(0, snap).value().total == 0);
}

BOOST_AUTO_TEST_CASE(pager_carries_unread_final_readings) {
    oar::UsagePager pager;
    std::vector<oar::UsageEntry> meters;
    for (std::uint64_t n = 1; n <= 50; ++n) {
        meters.push_back(usage(n, 1));
    }
    meters.push_back(usage(60, 2, true));
    auto source = meters;
    const auto snap = [&] { return std::exchange(source, {}); };
    BOOST_REQUIRE(pager.page(0, snap).has_value());  // first page only; the read stops
    // The switch forgot the final reading; the pager did not.
    source = {usage(1, 1)};
    auto again = pager.page(0, snap).value();
    BOOST_TEST(again.total == 2);
    BOOST_TEST(again.entries.back().detached);
    BOOST_TEST(again.entries.back().nic_id == 60U);
    // Read to the end: delivered, so the next snapshot drops it.
    source = {usage(1, 1)};
    BOOST_TEST(pager.page(0, snap).value().total == 1);
}

BOOST_AUTO_TEST_CASE(names) {
    BOOST_TEST(std::string_view{oar::to_string(Status::busy)} == "busy");
    BOOST_TEST(std::string_view{oar::to_string(oar::Role::gpu)} == "gpu");
    BOOST_TEST(std::string_view{oar::to_string(oar::HealthState::faulted)} == "faulted");
    BOOST_TEST(std::string_view{oar::to_string(BodyError::bad_chunk)} == "bad_chunk");
    BOOST_TEST(std::string_view{oar::to_string(BodyError::bad_geometry)} == "bad_geometry");
    BOOST_TEST(std::string_view{oar::to_string(BodyError::bad_key_length)} == "bad_key_length");
    BOOST_TEST(oar::role_serves(oar::Role::gpu, FunctionType::gpu_vf));
    BOOST_TEST(!oar::role_serves(oar::Role::net, FunctionType::blk_fn));
}

BOOST_AUTO_TEST_SUITE_END()
