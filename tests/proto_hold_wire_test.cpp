// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ Requirements 5.4 and 13.4: the hold
// wire protocol codec: header layout and checksum, every opcode's payload,
// block data with per-block CRC32C, and the strict decode.

#define BOOST_TEST_MODULE proto_hold_wire_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "common/crc32c.hpp"
#include "common/wire.hpp"
#include "proto/hold_wire.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;
using proto::HoldOpcode;
using proto::HoldStatus;

namespace {

constexpr std::uint64_t volume = 0x100;
constexpr std::uint64_t epoch = 9;
constexpr std::uint64_t attachment = 0xA1;
constexpr std::uint32_t generation = 2;
constexpr std::uint64_t lba = 0x1000;
constexpr std::size_t off_flags = 0x06;
constexpr std::size_t off_payload_len = 0x08;
constexpr std::size_t off_status = 0x0C;
constexpr std::size_t off_reserved = 0x0E;
constexpr std::size_t off_blocks = 0x34;
constexpr std::size_t off_reserved2 = 0x40;

// Owns the bytes BlockData spans point at.
struct Blocks {
    std::vector<std::byte> data;
    std::vector<std::byte> crcs;
    std::uint32_t block_size;

    Blocks(std::uint32_t n, std::uint32_t bs) : data(std::size_t{n} * bs), block_size{bs} {
        for (std::size_t i = 0; i < data.size(); ++i) {
            data[i] = std::byte{static_cast<std::uint8_t>((i * 13U) + 1U)};
        }
        crcs = proto::block_crcs(data, bs);
    }
    [[nodiscard]] auto view() const -> proto::BlockData {
        return {.block_size = block_size, .crcs = crcs, .data = data};
    }
};

auto header(HoldOpcode op, std::uint32_t blocks = 0, bool response = false) -> proto::HoldHeader {
    return {.opcode = op,
            .flags = response ? proto::hold_flags::response : std::uint16_t{0},
            .payload_len = 0,
            .status = HoldStatus::ok,
            .request_id = 77,
            .volume_id = volume,
            .epoch = epoch,
            .attachment_id = attachment,
            .generation = generation,
            .blocks = blocks,
            .lba = blocks != 0 ? lba : 0};
}

auto peer_header(HoldOpcode op, std::uint32_t blocks = 0, bool response = false)
    -> proto::HoldHeader {
    auto h = header(op, blocks, response);
    h.attachment_id = 0;
    h.generation = 0;
    return h;
}

auto encoded(const proto::HoldFrame& f) -> std::vector<std::byte> {
    auto b = proto::encode_hold_frame(f);
    BOOST_REQUIRE_MESSAGE(b.has_value(), proto::to_string(b.error()));
    return *b;
}

auto encode_error(const proto::HoldFrame& f) -> DecodeError {
    auto b = proto::encode_hold_frame(f);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto f = proto::decode_hold_frame(b);
    BOOST_REQUIRE(!f.has_value());
    return f.error();
}

// Rewrites the header CRC after a deliberate corruption, so the decoder
// gets past the checksum to the rule under test.
auto reseal(std::vector<std::byte>& b) -> void {
    const auto crc = ak::crc32c::of(std::span{b}.first(proto::hold_header_crc_offset));
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(proto::hold_header_crc_offset)};
    BOOST_REQUIRE(w.write(crc, ak::wire::Order::little).has_value());
}

template<std::unsigned_integral T>
auto set_at(std::vector<std::byte>& b, std::size_t off, T v) -> void {
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(off)};
    BOOST_REQUIRE(w.write(v, ak::wire::Order::little).has_value());
}

auto le64_at(std::span<const std::byte> b, std::size_t off) -> std::uint64_t {
    ak::wire::Reader r{b.subspan(off)};
    return r.le64().value_or(0);
}

const Blocks four_k{3, proto::block_size_4096};
const Blocks five_twelve{3, proto::block_size_512};

auto every_frame() -> std::vector<proto::HoldFrame> {
    using F = proto::HoldFrame;
    auto failed_read = header(HoldOpcode::read, 3, true);
    failed_read.status = HoldStatus::fenced;
    auto nack = peer_header(HoldOpcode::repl_ack, 0, true);
    nack.status = HoldStatus::stale_epoch;
    auto redirect = header(HoldOpcode::redirect, 0, true);
    redirect.status = HoldStatus::not_primary;
    auto hydrate = header(HoldOpcode::write, 3);
    hydrate.flags = proto::hold_flags::hydrate;
    return {
        F{header(HoldOpcode::hello), proto::HoldHello{.role = proto::HoldPeerRole::initiator}},
        F{peer_header(HoldOpcode::hello),
          proto::HoldHello{.role = proto::HoldPeerRole::peer, .replica_gen = 4}},
        F{header(HoldOpcode::hello_ok, 0, true),
          proto::HoldHelloOk{.block_size = 4096, .capacity_blocks = 1U << 18, .commit_seq = 5}},
        F{header(HoldOpcode::read, 3), std::monostate{}},
        F{header(HoldOpcode::read, 3, true), four_k.view()},
        F{failed_read, std::monostate{}},
        F{header(HoldOpcode::write, 3), four_k.view()},
        F{header(HoldOpcode::write, 3), five_twelve.view()},
        F{hydrate, four_k.view()},
        F{header(HoldOpcode::write, 3, true), std::monostate{}},
        F{header(HoldOpcode::write_zeroes, 8), std::monostate{}},
        F{header(HoldOpcode::discard, 8, true), std::monostate{}},
        F{header(HoldOpcode::flush), std::monostate{}},
        F{header(HoldOpcode::flush, 0, true), std::monostate{}},
        F{peer_header(HoldOpcode::repl_write, 3),
          proto::ReplWrite{
              .seq = 11, .commit_seq = 10, .op = proto::ReplOp::write, .data = four_k.view()}},
        F{peer_header(HoldOpcode::repl_write, 8),
          proto::ReplWrite{.seq = 12, .commit_seq = 0, .op = proto::ReplOp::discard, .data = {}}},
        F{peer_header(HoldOpcode::repl_ack, 0, true), proto::ReplAck{.seq = 11}},
        F{nack, proto::ReplAck{.seq = 12}},
        F{peer_header(HoldOpcode::intents), std::monostate{}},
        F{peer_header(HoldOpcode::intents, 0, true),
          proto::HoldIntents{.entries = {{.seq = 11, .lba = 0, .blocks = 3},
                                         {.seq = 12, .lba = 64, .blocks = 8}}}},
        F{peer_header(HoldOpcode::intents, 0, true), proto::HoldIntents{}},
        F{peer_header(HoldOpcode::sync_data, 3), proto::SyncData{.seq = 13, .data = four_k.view()}},
        F{peer_header(HoldOpcode::sync_data, 3, true), std::monostate{}},
        F{peer_header(HoldOpcode::hydrate_fill, 3), four_k.view()},
        F{header(HoldOpcode::ping), proto::HoldPing{.commit_seq = 10}},
        F{peer_header(HoldOpcode::ping, 0, true), proto::HoldPing{.commit_seq = 10}},
        F{redirect, proto::HoldRedirect{.primary_server = 0x22, .primary_epoch = 10}},
    };
}

}  // namespace

BOOST_AUTO_TEST_SUITE(hold_wire, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(every_frame_round_trips_canonically) {
    for (const auto& f : every_frame()) {
        const auto b = encoded(f);
        auto back = proto::decode_hold_frame(b);
        BOOST_REQUIRE_MESSAGE(back.has_value(), "opcode " << static_cast<int>(f.header.opcode)
                                                          << ": "
                                                          << proto::to_string(back.error()));
        auto want = f;
        want.header.payload_len = static_cast<std::uint32_t>(b.size() - proto::hold_header_size);
        BOOST_TEST((*back == want));
        BOOST_TEST((encoded(*back) == b));

        // Streaming: header first, then exactly payload_len bytes.
        auto h = proto::decode_hold_header(std::span{b}.first(proto::hold_header_size));
        BOOST_REQUIRE(h.has_value());
        auto p = proto::decode_hold_payload(*h, std::span{b}.subspan(proto::hold_header_size));
        BOOST_REQUIRE(p.has_value());
        BOOST_TEST((*p == f.payload));

        // A sender that writes the header and payload separately.
        auto split = proto::encode_hold_header(f.header, h->payload_len);
        BOOST_REQUIRE(split.has_value());
        BOOST_TEST(std::ranges::equal(*split, std::span{b}.first(proto::hold_header_size)));
    }
}

BOOST_AUTO_TEST_CASE(header_layout_is_little_endian) {
    const auto b = encoded({header(HoldOpcode::write, 3), four_k.view()});
    BOOST_TEST(b.size() == proto::hold_header_size + (3 * (4 + 4096)));
    const std::string_view magic{"AKHW"};
    for (std::size_t i = 0; i < magic.size(); ++i) {
        BOOST_TEST(std::to_integer<char>(b[i]) == magic[i]);
    }
    BOOST_TEST(std::to_integer<int>(b[4]) == 1);  // version
    BOOST_TEST(std::to_integer<int>(b[5]) == 4);  // write
    BOOST_TEST(le64_at(b, 0x10) == 77U);          // request_id
    BOOST_TEST(le64_at(b, 0x18) == volume);
    BOOST_TEST(le64_at(b, 0x20) == epoch);
    BOOST_TEST(le64_at(b, 0x28) == attachment);
    BOOST_TEST(std::to_integer<int>(b[0x30]) == 2);  // generation
    BOOST_TEST(std::to_integer<int>(b[0x34]) == 3);  // blocks
    BOOST_TEST(le64_at(b, 0x38) == lba);
    ak::wire::Reader r{std::span{b}.subspan(proto::hold_header_crc_offset)};
    BOOST_TEST(r.le32().value_or(0) ==
               ak::crc32c::of(std::span{b}.first(proto::hold_header_crc_offset)));
    // Block data: the checksums, then the blocks.
    BOOST_TEST(std::ranges::equal(std::span{b}.subspan(proto::hold_header_size, 12), four_k.crcs));
    BOOST_TEST(std::ranges::equal(std::span{b}.subspan(proto::hold_header_size + 12), four_k.data));
}

BOOST_AUTO_TEST_CASE(payload_layouts) {
    auto b = encoded(
        {peer_header(HoldOpcode::repl_write, 3),
         proto::ReplWrite{
             .seq = 11, .commit_seq = 10, .op = proto::ReplOp::write, .data = four_k.view()}});
    constexpr std::size_t p = proto::hold_header_size;
    BOOST_TEST(le64_at(b, p) == 11U);
    BOOST_TEST(le64_at(b, p + 8) == 10U);
    BOOST_TEST(std::to_integer<int>(b[p + 16]) == 1);  // op write
    BOOST_TEST(std::ranges::equal(std::span{b}.subspan(p + 24, 12), four_k.crcs));

    b = encoded({peer_header(HoldOpcode::intents, 0, true),
                 proto::HoldIntents{.entries = {{.seq = 11, .lba = 64, .blocks = 3}}}});
    BOOST_TEST(std::to_integer<int>(b[p]) == 1);  // count
    BOOST_TEST(le64_at(b, p + 8) == 11U);
    BOOST_TEST(le64_at(b, p + 16) == 64U);
    BOOST_TEST(std::to_integer<int>(b[p + 24]) == 3);

    b = encoded({header(HoldOpcode::hello_ok, 0, true),
                 proto::HoldHelloOk{.block_size = 512, .capacity_blocks = 9, .commit_seq = 5}});
    BOOST_TEST(std::to_integer<int>(b[p + 1]) == 2);  // 512
    BOOST_TEST(le64_at(b, p + 8) == 9U);
    BOOST_TEST(le64_at(b, p + 16) == 5U);
}

BOOST_AUTO_TEST_CASE(block_checksums_find_the_bad_block) {
    Blocks blocks{4, proto::block_size_512};
    BOOST_TEST(proto::first_bad_block(blocks.view()) == 4U);
    BOOST_TEST(proto::block_crc(blocks.view(), 0) ==
               ak::crc32c::of(std::span{blocks.data}.first(512)));
    blocks.data[(2 * 512) + 100] ^= std::byte{1};
    BOOST_TEST(proto::first_bad_block(blocks.view()) == 2U);

    // The codec carries checksums without judging them: verification is
    // the receiver's, so it can answer with the checksum status.
    const auto b = encoded({header(HoldOpcode::write, 4), blocks.view()});
    auto f = proto::decode_hold_frame(b);
    BOOST_REQUIRE(f.has_value());
    BOOST_TEST(proto::first_bad_block(std::get<proto::BlockData>(f->payload)) == 2U);
}

BOOST_AUTO_TEST_CASE(header_checksum_is_checked_first) {
    const auto good = encoded({header(HoldOpcode::flush), std::monostate{}});
    for (std::size_t off = 5; off < proto::hold_header_size; ++off) {
        auto b = good;
        b[off] ^= std::byte{0x40};
        BOOST_TEST((decode_error(b) == DecodeError::bad_header_crc), "offset " << off);
    }
    auto b = good;
    b[0] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
}

BOOST_AUTO_TEST_CASE(header_rules_in_decode) {
    const auto good = encoded({header(HoldOpcode::flush), std::monostate{}});
    const auto refused = [&](auto mutate) {
        auto b = good;
        mutate(b);
        reseal(b);
        return decode_error(std::span{b}.first(proto::hold_header_size));
    };
    BOOST_TEST((refused([](auto& b) { b[5] = std::byte{0}; }) == DecodeError::unknown_value));
    BOOST_TEST((refused([](auto& b) { b[5] = std::byte{15}; }) == DecodeError::unknown_value));
    BOOST_TEST((refused([](auto& b) { set_at<std::uint16_t>(b, off_flags, 4); }) ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((refused([](auto& b) { b[off_reserved] = std::byte{1}; }) ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((refused([](auto& b) { b[off_reserved2 + 3] = std::byte{1}; }) ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((refused([](auto& b) {
                    set_at<std::uint32_t>(b, off_payload_len,
                                          static_cast<std::uint32_t>(proto::max_hold_payload + 1));
                }) == DecodeError::record_too_large));
    BOOST_TEST((refused([](auto& b) { set_at<std::uint16_t>(b, off_status, 13); }) ==
                DecodeError::unknown_value));
    // A request carrying a failure status.
    BOOST_TEST((refused([](auto& b) { set_at<std::uint16_t>(b, off_status, 1); }) ==
                DecodeError::bad_hold_direction));
    // flush has no block range.
    BOOST_TEST((refused([](auto& b) { set_at<std::uint32_t>(b, off_blocks, 1); }) ==
                DecodeError::bad_block_range));
}

BOOST_AUTO_TEST_CASE(header_rules_in_encode) {
    struct Case {
        proto::HoldHeader h;
        DecodeError want;
    };
    auto h = [](auto mutate) {
        auto x = header(HoldOpcode::read, 1);
        mutate(x);
        return x;
    };
    const Case cases[] = {
        {h([](auto& x) { x.volume_id = 0; }), DecodeError::bad_id},
        {h([](auto& x) { x.epoch = 0; }), DecodeError::bad_epoch},
        {h([](auto& x) { x.generation = 0; }), DecodeError::bad_id},
        {h([](auto& x) { x.attachment_id = 0; }), DecodeError::bad_id},
        {h([](auto& x) { x.blocks = 0; }), DecodeError::bad_block_range},
        {h([](auto& x) { x.blocks = proto::max_hold_blocks + 1; }), DecodeError::bad_block_range},
        {h([](auto& x) { x.lba = UINT64_MAX; }), DecodeError::bad_block_range},
        {h([](auto& x) { x.flags = proto::hold_flags::hydrate; }), DecodeError::bad_hold_direction},
        {h([](auto& x) { x.opcode = HoldOpcode::hello_ok; }), DecodeError::bad_hold_direction},
        {h([](auto& x) { x.opcode = HoldOpcode::repl_ack; }), DecodeError::bad_hold_direction},
        {h([](auto& x) { x.opcode = HoldOpcode::redirect; }), DecodeError::bad_hold_direction},
        {h([](auto& x) {
             x.opcode = HoldOpcode::hello;
             x.flags = proto::hold_flags::response;
         }),
         DecodeError::bad_hold_direction},
        {h([](auto& x) {
             x.opcode = HoldOpcode::repl_write;
             x.flags = proto::hold_flags::response;
         }),
         DecodeError::bad_hold_direction},
        {h([](auto& x) {
             x.flags = proto::hold_flags::response | proto::hold_flags::hydrate;
             x.opcode = HoldOpcode::write;
         }),
         DecodeError::bad_hold_direction},
        {h([](auto& x) { x.opcode = HoldOpcode::ping; }), DecodeError::bad_block_range},
    };
    for (const auto& c : cases) {
        auto b = proto::encode_hold_header(c.h, 0);
        BOOST_REQUIRE(!b.has_value());
        BOOST_TEST((b.error() == c.want));
    }
    BOOST_TEST((
        proto::encode_hold_header(header(HoldOpcode::flush), proto::max_hold_payload + 1).error() ==
        DecodeError::record_too_large));
}

BOOST_AUTO_TEST_CASE(payload_rules) {
    using F = proto::HoldFrame;
    auto big_read = header(HoldOpcode::read, 2048, true);
    std::vector<std::byte> big(std::size_t{2048} * 4096);
    std::vector<std::byte> big_crcs(std::size_t{2048} * 4);
    const std::pair<F, DecodeError> cases[] = {
        // Payload shape must match the header.
        {F{header(HoldOpcode::read, 3), four_k.view()}, DecodeError::bad_payload_size},
        {F{header(HoldOpcode::write, 3), std::monostate{}}, DecodeError::bad_payload_size},
        {F{header(HoldOpcode::write, 2), four_k.view()}, DecodeError::bad_payload_size},
        {F{header(HoldOpcode::ping), std::monostate{}}, DecodeError::bad_payload_size},
        // Data over 4 MiB: 2048 blocks of 4096.
        {F{big_read, proto::BlockData{.block_size = 4096, .crcs = big_crcs, .data = big}},
         DecodeError::record_too_large},
        // hello: the role must fit the session.
        {F{header(HoldOpcode::hello),
           proto::HoldHello{.role = proto::HoldPeerRole::peer, .replica_gen = 1}},
         DecodeError::bad_id},
        {F{header(HoldOpcode::hello),
           proto::HoldHello{.role = proto::HoldPeerRole::initiator, .replica_gen = 1}},
         DecodeError::bad_id},
        {F{peer_header(HoldOpcode::hello), proto::HoldHello{.role = proto::HoldPeerRole::peer}},
         DecodeError::bad_id},
        {F{header(HoldOpcode::hello),
           proto::HoldHello{.role = static_cast<proto::HoldPeerRole>(3)}},
         DecodeError::unknown_value},
        {F{header(HoldOpcode::hello_ok, 0, true),
           proto::HoldHelloOk{.block_size = 1024, .capacity_blocks = 1}},
         DecodeError::bad_block_size},
        {F{header(HoldOpcode::hello_ok, 0, true),
           proto::HoldHelloOk{.block_size = 512, .capacity_blocks = 0}},
         DecodeError::bad_id},
        // repl_write: seq ordering, op, data presence.
        {F{peer_header(HoldOpcode::repl_write, 8),
           proto::ReplWrite{.seq = 0, .op = proto::ReplOp::discard, .data = {}}},
         DecodeError::bad_id},
        {F{peer_header(HoldOpcode::repl_write, 8),
           proto::ReplWrite{.seq = 5, .commit_seq = 5, .op = proto::ReplOp::discard, .data = {}}},
         DecodeError::bad_id},
        {F{peer_header(HoldOpcode::repl_write, 8),
           proto::ReplWrite{.seq = 5, .op = static_cast<proto::ReplOp>(4), .data = {}}},
         DecodeError::unknown_value},
        {F{peer_header(HoldOpcode::repl_write, 3),
           proto::ReplWrite{.seq = 5, .op = proto::ReplOp::discard, .data = four_k.view()}},
         DecodeError::bad_payload_size},
        {F{peer_header(HoldOpcode::repl_write, 3),
           proto::ReplWrite{.seq = 5, .op = proto::ReplOp::write, .data = {}}},
         DecodeError::bad_payload_size},
        {F{peer_header(HoldOpcode::repl_ack, 0, true), proto::ReplAck{.seq = 0}},
         DecodeError::bad_id},
        // intents: ordering and ranges.
        {F{peer_header(HoldOpcode::intents, 0, true),
           proto::HoldIntents{
               .entries = {{.seq = 2, .lba = 0, .blocks = 1}, {.seq = 2, .lba = 8, .blocks = 1}}}},
         DecodeError::not_ascending},
        {F{peer_header(HoldOpcode::intents, 0, true),
           proto::HoldIntents{.entries = {{.seq = 0, .lba = 0, .blocks = 1}}}},
         DecodeError::bad_id},
        {F{peer_header(HoldOpcode::intents, 0, true),
           proto::HoldIntents{.entries = {{.seq = 1, .lba = 0, .blocks = 0}}}},
         DecodeError::bad_block_range},
        {F{peer_header(HoldOpcode::sync_data, 3), proto::SyncData{.seq = 0, .data = four_k.view()}},
         DecodeError::bad_id},
    };
    for (const auto& [f, want] : cases) {
        BOOST_TEST((encode_error(f) == want),
                   "opcode " << static_cast<int>(f.header.opcode) << " got "
                             << proto::to_string(proto::encode_hold_frame(f).error()));
    }
    // 1024 blocks of 4096 is exactly 4 MiB and allowed.
    auto max_read = header(HoldOpcode::read, 1024, true);
    BOOST_TEST(
        proto::encode_hold_frame(
            {max_read, proto::BlockData{.block_size = 4096,
                                        .crcs = std::span{big_crcs}.first(4096),
                                        .data = std::span{big}.first(std::size_t{4} << 20U)}})
            .has_value());
}

BOOST_AUTO_TEST_CASE(payload_decode_is_strict) {
    // A payload length that does not split into whole 512 or 4096 blocks.
    auto b = encoded({header(HoldOpcode::write, 3), four_k.view()});
    const auto shrink = [](std::vector<std::byte> v, std::size_t by) {
        v.resize(v.size() - by);
        set_at<std::uint32_t>(v, off_payload_len,
                              static_cast<std::uint32_t>(v.size() - proto::hold_header_size));
        reseal(v);
        return v;
    };
    BOOST_TEST((decode_error(shrink(b, 3)) == DecodeError::bad_payload_size));
    // 3 x (4 + 1024): a whole number per block, but not a block size.
    BOOST_TEST((decode_error(shrink(b, 3 * 3072)) == DecodeError::bad_payload_size));
    // Same total as 3 x 4096 + 12 but relabelled as 4 blocks.
    auto relabel = b;
    set_at<std::uint32_t>(relabel, off_blocks, 4);
    reseal(relabel);
    BOOST_TEST((decode_error(relabel) == DecodeError::bad_payload_size));

    // Reserved bytes inside payloads.
    const auto with = [](const proto::HoldFrame& f, std::size_t off) {
        auto v = encoded(f);
        v[proto::hold_header_size + off] = std::byte{1};
        return decode_error(v);
    };
    BOOST_TEST((with({header(HoldOpcode::hello), proto::HoldHello{}}, 2) ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((with({header(HoldOpcode::hello_ok, 0, true),
                      proto::HoldHelloOk{.block_size = 4096, .capacity_blocks = 1}},
                     5) == DecodeError::reserved_not_zero));
    BOOST_TEST((with({peer_header(HoldOpcode::repl_write, 8),
                      proto::ReplWrite{.seq = 5, .op = proto::ReplOp::discard, .data = {}}},
                     20) == DecodeError::reserved_not_zero));
    BOOST_TEST((with({peer_header(HoldOpcode::intents, 0, true),
                      proto::HoldIntents{.entries = {{.seq = 1, .lba = 0, .blocks = 1}}}},
                     4) == DecodeError::reserved_not_zero));
    BOOST_TEST((with({peer_header(HoldOpcode::intents, 0, true),
                      proto::HoldIntents{.entries = {{.seq = 1, .lba = 0, .blocks = 1}}}},
                     8 + 20) == DecodeError::reserved_not_zero));

    // A hostile intent count is refused before anything is allocated.
    auto in = encoded({peer_header(HoldOpcode::intents, 0, true), proto::HoldIntents{}});
    set_at<std::uint32_t>(in, proto::hold_header_size, 0xFFFF'FFFF);
    BOOST_TEST((decode_error(in) == DecodeError::too_many_entries));
    set_at<std::uint32_t>(in, proto::hold_header_size, 1);
    BOOST_TEST((decode_error(in) == DecodeError::bad_payload_size));

    // decode_hold_payload refuses a buffer that is not payload_len long.
    const auto good = encoded({header(HoldOpcode::ping), proto::HoldPing{.commit_seq = 1}});
    auto h = proto::decode_hold_header(std::span{good}.first(proto::hold_header_size));
    BOOST_REQUIRE(h.has_value());
    BOOST_TEST((proto::decode_hold_payload(*h, std::span{good}.subspan(proto::hold_header_size + 1))
                    .error() == DecodeError::bad_payload_size));
}

BOOST_AUTO_TEST_CASE(lengths) {
    const auto good = encoded({peer_header(HoldOpcode::sync_data, 3),
                               proto::SyncData{.seq = 1, .data = five_twelve.view()}});
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
    BOOST_TEST(
        (proto::decode_hold_header(std::span{good}.first(proto::hold_header_size + 1)).error() ==
         DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {DecodeError::bad_header_crc, DecodeError::bad_block_range,
                   DecodeError::bad_payload_size, DecodeError::bad_hold_direction}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
