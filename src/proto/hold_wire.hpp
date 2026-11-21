// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The hold wire protocol: frames between oar-blk's NetworkVolumeBackend
// (the initiator) and hold roles, and between hold roles
// (.kiro/specs/block-volume-service/ design "hold wire protocol",
// Requirements 5.4 and 13.4). It runs inside mutually authenticated
// TLS 1.3; this header only frames, checks and lays out bytes. Who may say
// what (epoch fencing, attachment generations, roles) is the receiver's
// job.
//
// Every frame is a 72-byte header and payload_len payload bytes. A reader
// takes the header first (decode_hold_header), learns payload_len, then
// reads exactly that many bytes and decodes them against the header
// (decode_hold_payload). Block data is not copied: the decoded payload
// holds spans into the caller's buffer.
//
// Header (little-endian):
//   0x00  magic          u32  'AKHW'
//   0x04  version        u8   1
//   0x05  opcode         u8   HoldOpcode
//   0x06  flags          u16  hold_flags; other bits zero
//   0x08  payload_len    u32  at most max_hold_payload
//   0x0C  status         u16  HoldStatus; ok unless the response flag is set
//   0x0E  reserved       u16  zero
//   0x10  request_id     u64  initiator's ID, echoed in the response
//   0x18  volume_id      u64  non-zero
//   0x20  epoch          u64  sender's epoch for the volume; non-zero
//   0x28  attachment_id  u64  initiator sessions; 0 between hold roles
//   0x30  generation     u32  non-zero exactly when attachment_id is
//   0x34  blocks         u32  1 to max_hold_blocks for block opcodes, else 0
//   0x38  lba            u64  first block for block opcodes, else 0
//   0x40  reserved       u32  zero
//   0x44  header_crc32c  u32  CRC32C of bytes [0x00, 0x44)
//
// Opcodes and payloads ("R" is the response flag; a response echoes the
// request's request_id, lba and blocks):
//   hello         ->  role u8 | reserved [3] | replica_gen u32
//                     initiator: attachment_id and generation set, replica_gen 0
//                     peer:      attachment_id 0, replica_gen non-zero
//   hello_ok  R   <-  block_size u32 | reserved u32 | capacity_blocks u64 | commit_seq u64
//   read          ->  empty;  R: block data
//   write         ->  block data (flag hydrate: fill only unwritten blocks);  R: empty
//   write_zeroes  ->  empty;  R: empty
//   discard       ->  empty;  R: empty
//   flush         ->  empty;  R: empty
//   repl_write    ->  seq u64 | commit_seq u64 | op u8 | reserved [7] | block data if op write
//                     (never R; the member answers with repl_ack)
//   repl_ack  R   <-  seq u64 (also on a failure status)
//   intents       ->  empty;  R: count u32 | reserved u32 | count x 24:
//                     seq u64 | lba u64 | blocks u32 | reserved u32, seq strictly ascending
//   sync_data     ->  seq u64 | block data;  R: empty
//   hydrate_fill  ->  block data;  R: empty
//   ping          ->  commit_seq u64;  R: commit_seq u64
//   redirect  R   <-  primary_server u64 | primary_epoch u64 (0: unknown), any status
//
// Block data is blocks x 4 bytes of CRC32C (one per block, over its
// ciphertext) followed by blocks x block_size bytes; block_size (512 or
// 4096) follows from payload_len, and the data is at most
// max_hold_data_bytes. A response with a status other than ok has an
// empty payload, except repl_ack and redirect, which always carry theirs.
//
// Block opcodes: read, write, write_zeroes, discard, repl_write,
// sync_data, hydrate_fill.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/crc32c.hpp"
#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/replica_config.hpp"

namespace ak::proto {

inline constexpr std::uint32_t hold_magic = 0x5748'4B41;  // "AKHW" as little-endian bytes
inline constexpr std::uint8_t hold_version = 1;
inline constexpr std::size_t hold_header_size = 72;
inline constexpr std::size_t hold_header_crc_offset = 0x44;
inline constexpr std::uint32_t max_hold_blocks = 2048;
inline constexpr std::size_t max_hold_data_bytes = std::size_t{4} << 20U;  // 4 MiB
inline constexpr std::size_t hold_block_crc_size = 4;
inline constexpr std::size_t max_hold_intents = 4096;  // the replica's intent ring
inline constexpr std::size_t hold_intent_size = 24;
inline constexpr std::size_t hold_hello_size = 8;
inline constexpr std::size_t hold_hello_ok_size = 24;
inline constexpr std::size_t hold_repl_prefix_size = 24;
inline constexpr std::size_t hold_seq_size = 8;
inline constexpr std::size_t hold_redirect_size = 16;
inline constexpr std::size_t hold_intents_fixed_size = 8;
inline constexpr std::size_t max_hold_payload =
    hold_repl_prefix_size + (max_hold_blocks * hold_block_crc_size) + max_hold_data_bytes;

// Values are part of the wire protocol: never renumber.
enum class HoldOpcode : std::uint8_t {
    hello = 1,
    hello_ok = 2,
    read = 3,
    write = 4,
    write_zeroes = 5,
    discard = 6,
    flush = 7,
    repl_write = 8,
    repl_ack = 9,
    intents = 10,
    sync_data = 11,
    hydrate_fill = 12,
    ping = 13,
    redirect = 14,
};

namespace hold_flags {
inline constexpr std::uint16_t response = 0x1;
inline constexpr std::uint16_t hydrate = 0x2;  // write / repl_write: fill unwritten blocks only
inline constexpr std::uint16_t all = response | hydrate;
}  // namespace hold_flags

enum class HoldStatus : std::uint16_t {
    ok = 0,
    stale_epoch = 1,   // the request's epoch is older than the receiver's
    fenced = 2,        // the attachment generation is retired
    not_primary = 3,   // see redirect
    read_only = 4,     // a write from a read-only attachment
    not_hydrated = 5,  // foreign-key restore: oar-blk must hydrate first
    throttled = 6,     // over the volume's QoS limit at the primary
    checksum = 7,      // a block's CRC32C did not match its data
    io_suspended = 8,  // no in-sync replica
    range = 9,         // past the volume's capacity
    io_error = 10,     // media error that could not be repaired
    bad_request = 11,  // well-formed but not acceptable in this session
    unknown_volume = 12,
};

enum class HoldPeerRole : std::uint8_t {
    initiator = 1,
    peer = 2,
};

enum class ReplOp : std::uint8_t {
    write = 1,
    write_zeroes = 2,
    discard = 3,
};

struct HoldHeader {
    HoldOpcode opcode{HoldOpcode::ping};
    std::uint16_t flags{0};
    std::uint32_t payload_len{0};  // set by encode_hold_frame
    HoldStatus status{HoldStatus::ok};
    std::uint64_t request_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint64_t attachment_id{0};
    std::uint32_t generation{0};
    std::uint32_t blocks{0};
    std::uint64_t lba{0};
    friend auto operator==(const HoldHeader&, const HoldHeader&) -> bool = default;
};

// Blocks with their checksums. Decoded payloads point into the frame.
struct BlockData {
    std::uint32_t block_size{block_size_4096};
    std::span<const std::byte> crcs;  // blocks x 4, little-endian CRC32C
    std::span<const std::byte> data;  // blocks x block_size
    friend auto operator==(const BlockData& a, const BlockData& b) -> bool {
        return a.block_size == b.block_size && std::ranges::equal(a.crcs, b.crcs) &&
               std::ranges::equal(a.data, b.data);
    }
};

struct HoldHello {
    HoldPeerRole role{HoldPeerRole::initiator};
    std::uint32_t replica_gen{0};
    friend auto operator==(const HoldHello&, const HoldHello&) -> bool = default;
};

struct HoldHelloOk {
    std::uint32_t block_size{block_size_4096};
    std::uint64_t capacity_blocks{0};
    std::uint64_t commit_seq{0};
    friend auto operator==(const HoldHelloOk&, const HoldHelloOk&) -> bool = default;
};

struct ReplWrite {
    std::uint64_t seq{0};
    std::uint64_t commit_seq{0};  // below seq
    ReplOp op{ReplOp::write};
    BlockData data;  // empty unless op is write
    friend auto operator==(const ReplWrite&, const ReplWrite&) -> bool = default;
};

struct ReplAck {
    std::uint64_t seq{0};
    friend auto operator==(const ReplAck&, const ReplAck&) -> bool = default;
};

struct HoldIntent {
    std::uint64_t seq{0};
    std::uint64_t lba{0};
    std::uint32_t blocks{0};
    friend auto operator==(const HoldIntent&, const HoldIntent&) -> bool = default;
};

struct HoldIntents {
    std::vector<HoldIntent> entries;  // seq strictly ascending
    friend auto operator==(const HoldIntents&, const HoldIntents&) -> bool = default;
};

struct SyncData {
    std::uint64_t seq{0};  // the primary's position in the ordered stream
    BlockData data;
    friend auto operator==(const SyncData&, const SyncData&) -> bool = default;
};

struct HoldPing {
    std::uint64_t commit_seq{0};
    friend auto operator==(const HoldPing&, const HoldPing&) -> bool = default;
};

struct HoldRedirect {
    std::uint64_t primary_server{0};
    std::uint64_t primary_epoch{0};
    friend auto operator==(const HoldRedirect&, const HoldRedirect&) -> bool = default;
};

using HoldPayload = std::variant<std::monostate, HoldHello, HoldHelloOk, BlockData, ReplWrite,
                                 ReplAck, HoldIntents, SyncData, HoldPing, HoldRedirect>;

struct HoldFrame {
    HoldHeader header;
    HoldPayload payload;
    friend auto operator==(const HoldFrame&, const HoldFrame&) -> bool = default;
};

[[nodiscard]] constexpr auto is_response(const HoldHeader& h) noexcept -> bool {
    return (h.flags & hold_flags::response) != 0;
}

[[nodiscard]] constexpr auto is_block_opcode(HoldOpcode op) noexcept -> bool {
    switch (op) {
        case HoldOpcode::read:
        case HoldOpcode::write:
        case HoldOpcode::write_zeroes:
        case HoldOpcode::discard:
        case HoldOpcode::repl_write:
        case HoldOpcode::sync_data:
        case HoldOpcode::hydrate_fill:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] constexpr auto block_data_size(std::uint32_t blocks,
                                             std::uint32_t block_size) noexcept -> std::size_t {
    return std::size_t{blocks} * (hold_block_crc_size + block_size);
}

// The CRC32C stored for block i of `d` (no bounds check beyond the span's).
[[nodiscard]] inline auto block_crc(const BlockData& d, std::size_t i) noexcept -> std::uint32_t {
    wire::Reader r{d.crcs.subspan(std::min(d.crcs.size(), i * hold_block_crc_size))};
    return r.le32().value_or(0);
}

// The index of the first block whose CRC32C does not match its data, or
// the block count when all match.
[[nodiscard]] inline auto first_bad_block(const BlockData& d) noexcept -> std::size_t {
    const std::size_t n = d.crcs.size() / hold_block_crc_size;
    for (std::size_t i = 0; i < n; ++i) {
        const auto block = d.data.subspan(i * d.block_size, d.block_size);
        if (crc32c::of(block) != block_crc(d, i)) {
            return i;
        }
    }
    return n;
}

// Computes the checksum array for `data` (a whole number of blocks).
[[nodiscard]] inline auto block_crcs(std::span<const std::byte> data, std::uint32_t block_size)
    -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve((data.size() / block_size) * hold_block_crc_size);
    wire::Writer w{out};
    for (std::size_t off = 0; off + block_size <= data.size(); off += block_size) {
        w.le32(crc32c::of(data.subspan(off, block_size)));
    }
    return out;
}

namespace detail {

[[nodiscard]] constexpr auto known(HoldOpcode op) noexcept -> bool {
    return op >= HoldOpcode::hello && op <= HoldOpcode::redirect;
}
[[nodiscard]] constexpr auto known(HoldStatus s) noexcept -> bool {
    return s <= HoldStatus::unknown_volume;
}
[[nodiscard]] constexpr auto known(HoldPeerRole r) noexcept -> bool {
    return r == HoldPeerRole::initiator || r == HoldPeerRole::peer;
}
[[nodiscard]] constexpr auto known(ReplOp op) noexcept -> bool {
    return op >= ReplOp::write && op <= ReplOp::discard;
}

// Rules on the header alone (everything but magic, version and the CRC).
[[nodiscard]] inline auto check_hold_header(const HoldHeader& h) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(h.opcode) || !known(h.status)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if ((h.flags & ~hold_flags::all) != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (h.payload_len > max_hold_payload) {
        return std::unexpected(DecodeError::record_too_large);
    }
    if (h.volume_id == 0 || (h.attachment_id == 0) != (h.generation == 0)) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (h.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    const bool resp = is_response(h);
    // Responses only: hello_ok, repl_ack, redirect. Requests only: hello,
    // repl_write. The rest go both ways.
    const bool must_respond = h.opcode == HoldOpcode::hello_ok ||
                              h.opcode == HoldOpcode::repl_ack || h.opcode == HoldOpcode::redirect;
    const bool must_request = h.opcode == HoldOpcode::hello || h.opcode == HoldOpcode::repl_write;
    if ((must_respond && !resp) || (must_request && resp) ||
        (!resp && h.status != HoldStatus::ok)) {
        return std::unexpected(DecodeError::bad_hold_direction);
    }
    if ((h.flags & hold_flags::hydrate) != 0 &&
        (resp || (h.opcode != HoldOpcode::write && h.opcode != HoldOpcode::repl_write))) {
        return std::unexpected(DecodeError::bad_hold_direction);
    }
    if (is_block_opcode(h.opcode)) {
        if (h.blocks == 0 || h.blocks > max_hold_blocks || h.lba > UINT64_MAX - h.blocks) {
            return std::unexpected(DecodeError::bad_block_range);
        }
    } else if (h.blocks != 0 || h.lba != 0) {
        return std::unexpected(DecodeError::bad_block_range);
    }
    return {};
}

// Splits block data off `bytes`; its size must be exactly the header's
// blocks at 512 or 4096 bytes each.
[[nodiscard]] inline auto read_block_data(const HoldHeader& h, std::span<const std::byte> bytes)
    -> std::expected<BlockData, DecodeError> {
    const std::size_t per_block = bytes.size() / h.blocks;
    if (per_block * h.blocks != bytes.size() || per_block <= hold_block_crc_size) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    const auto block_size = static_cast<std::uint32_t>(per_block - hold_block_crc_size);
    if (block_size != block_size_512 && block_size != block_size_4096) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    if (std::size_t{h.blocks} * block_size > max_hold_data_bytes) {
        return std::unexpected(DecodeError::record_too_large);
    }
    const std::size_t crc_bytes = std::size_t{h.blocks} * hold_block_crc_size;
    return BlockData{
        .block_size = block_size, .crcs = bytes.first(crc_bytes), .data = bytes.subspan(crc_bytes)};
}

// The checks read_block_data makes, for the encoder.
[[nodiscard]] inline auto check_block_data(const HoldHeader& h, const BlockData& d) noexcept
    -> std::expected<void, DecodeError> {
    if ((d.block_size != block_size_512 && d.block_size != block_size_4096) ||
        d.crcs.size() != std::size_t{h.blocks} * hold_block_crc_size ||
        d.data.size() != std::size_t{h.blocks} * d.block_size) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    if (d.data.size() > max_hold_data_bytes) {
        return std::unexpected(DecodeError::record_too_large);
    }
    return {};
}

// Which payload alternative a header calls for.
enum class Shape : std::uint8_t {
    empty,
    hello,
    hello_ok,
    blocks,
    repl_write,
    repl_ack,
    intents,
    sync_data,
    ping,
    redirect,
};

[[nodiscard]] constexpr auto shape_of(const HoldHeader& h) noexcept -> Shape {
    const bool resp = is_response(h);
    switch (h.opcode) {
        case HoldOpcode::repl_ack:
            return Shape::repl_ack;
        case HoldOpcode::redirect:
            return Shape::redirect;
        default:
            break;
    }
    if (resp && h.status != HoldStatus::ok) {
        return Shape::empty;
    }
    switch (h.opcode) {
        case HoldOpcode::hello:
            return Shape::hello;
        case HoldOpcode::hello_ok:
            return Shape::hello_ok;
        case HoldOpcode::read:
            return resp ? Shape::blocks : Shape::empty;
        case HoldOpcode::write:
        case HoldOpcode::hydrate_fill:
            return resp ? Shape::empty : Shape::blocks;
        case HoldOpcode::repl_write:
            return Shape::repl_write;
        case HoldOpcode::intents:
            return resp ? Shape::intents : Shape::empty;
        case HoldOpcode::sync_data:
            return resp ? Shape::empty : Shape::sync_data;
        case HoldOpcode::ping:
            return Shape::ping;
        default:
            return Shape::empty;
    }
}

[[nodiscard]] constexpr auto shape_of(const HoldPayload& p) noexcept -> Shape {
    // HoldPayload's alternatives are in Shape order.
    return static_cast<Shape>(p.index());
}

[[nodiscard]] inline auto check_payload(const HoldHeader& h, const HoldPayload& p)
    -> std::expected<void, DecodeError> {
    if (shape_of(p) != shape_of(h)) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    if (const auto* hello = std::get_if<HoldHello>(&p)) {
        if (!known(hello->role)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        const bool initiator = hello->role == HoldPeerRole::initiator;
        if (initiator != (h.attachment_id != 0) || initiator != (hello->replica_gen == 0)) {
            return std::unexpected(DecodeError::bad_id);
        }
    } else if (const auto* ok = std::get_if<HoldHelloOk>(&p)) {
        if (ok->block_size != block_size_512 && ok->block_size != block_size_4096) {
            return std::unexpected(DecodeError::bad_block_size);
        }
        if (ok->capacity_blocks == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
    } else if (const auto* d = std::get_if<BlockData>(&p)) {
        return check_block_data(h, *d);
    } else if (const auto* rw = std::get_if<ReplWrite>(&p)) {
        if (!known(rw->op)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (rw->seq == 0 || rw->commit_seq >= rw->seq) {
            return std::unexpected(DecodeError::bad_id);
        }
        if ((h.flags & hold_flags::hydrate) != 0 && rw->op != ReplOp::write) {
            return std::unexpected(DecodeError::bad_hold_direction);
        }
        if (rw->op == ReplOp::write) {
            return check_block_data(h, rw->data);
        }
        if (!rw->data.crcs.empty() || !rw->data.data.empty()) {
            return std::unexpected(DecodeError::bad_payload_size);
        }
    } else if (const auto* ack = std::get_if<ReplAck>(&p)) {
        if (ack->seq == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
    } else if (const auto* in = std::get_if<HoldIntents>(&p)) {
        if (in->entries.size() > max_hold_intents) {
            return std::unexpected(DecodeError::too_many_entries);
        }
        for (const auto& e : in->entries) {
            if (e.seq == 0) {
                return std::unexpected(DecodeError::bad_id);
            }
            if (e.blocks == 0 || e.blocks > max_hold_blocks || e.lba > UINT64_MAX - e.blocks) {
                return std::unexpected(DecodeError::bad_block_range);
            }
        }
        if (std::ranges::adjacent_find(in->entries, std::ranges::greater_equal{},
                                       &HoldIntent::seq) != in->entries.end()) {
            return std::unexpected(DecodeError::not_ascending);
        }
    } else if (const auto* sd = std::get_if<SyncData>(&p)) {
        if (sd->seq == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        return check_block_data(h, sd->data);
    }
    return {};
}

[[nodiscard]] inline auto payload_size(const HoldPayload& p) noexcept -> std::size_t {
    return std::visit(
        []<typename T>(const T& v) -> std::size_t {
            if constexpr (std::is_same_v<T, std::monostate>) {
                return 0;
            } else if constexpr (std::is_same_v<T, HoldHello>) {
                return hold_hello_size;
            } else if constexpr (std::is_same_v<T, HoldHelloOk>) {
                return hold_hello_ok_size;
            } else if constexpr (std::is_same_v<T, BlockData>) {
                return v.crcs.size() + v.data.size();
            } else if constexpr (std::is_same_v<T, ReplWrite>) {
                return hold_repl_prefix_size + v.data.crcs.size() + v.data.data.size();
            } else if constexpr (std::is_same_v<T, ReplAck> || std::is_same_v<T, HoldPing>) {
                return hold_seq_size;
            } else if constexpr (std::is_same_v<T, HoldIntents>) {
                return hold_intents_fixed_size + (v.entries.size() * hold_intent_size);
            } else if constexpr (std::is_same_v<T, SyncData>) {
                return hold_seq_size + v.data.crcs.size() + v.data.data.size();
            } else {
                static_assert(std::is_same_v<T, HoldRedirect>);
                return hold_redirect_size;
            }
        },
        p);
}

}  // namespace detail

// Decodes and checks a frame header: magic, version, CRC, reserved bytes
// and the header rules above. `bytes` is exactly the 72 header bytes.
[[nodiscard]] inline auto decode_hold_header(std::span<const std::byte> bytes)
    -> std::expected<HoldHeader, DecodeError> {
    if (bytes.size() < hold_header_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > hold_header_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.u8().value_or(0);
    HoldHeader h;
    h.opcode = static_cast<HoldOpcode>(r.u8().value_or(0));
    h.flags = r.le16().value_or(0);
    h.payload_len = r.le32().value_or(0);
    h.status = static_cast<HoldStatus>(r.le16().value_or(0));
    bool zero = r.le16().value_or(1) == 0;
    h.request_id = r.le64().value_or(0);
    h.volume_id = r.le64().value_or(0);
    h.epoch = r.le64().value_or(0);
    h.attachment_id = r.le64().value_or(0);
    h.generation = r.le32().value_or(0);
    h.blocks = r.le32().value_or(0);
    h.lba = r.le64().value_or(0);
    zero = r.le32().value_or(1) == 0 && zero;
    const auto crc = r.le32().value_or(0);
    if (magic != hold_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != hold_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    // The checksum before anything else in the header is believed.
    if (crc32c::of(bytes.first(hold_header_crc_offset)) != crc) {
        return std::unexpected(DecodeError::bad_header_crc);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_hold_header(h); !ok) {
        return std::unexpected(ok.error());
    }
    return h;
}

// Decodes the payload that follows `header` (which decode_hold_header
// accepted). `bytes` must be exactly header.payload_len bytes; block data
// in the result points into it.
[[nodiscard]] inline auto decode_hold_payload(const HoldHeader& header,
                                              std::span<const std::byte> bytes)
    -> std::expected<HoldPayload, DecodeError> {
    if (bytes.size() != header.payload_len) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    wire::Reader r{bytes};
    const auto exact = [&](std::size_t n) -> std::expected<void, DecodeError> {
        if (bytes.size() != n) {
            return std::unexpected(DecodeError::bad_payload_size);
        }
        return {};
    };
    HoldPayload out;
    switch (detail::shape_of(header)) {
        case detail::Shape::empty:
            if (auto ok = exact(0); !ok) {
                return std::unexpected(ok.error());
            }
            break;
        case detail::Shape::hello: {
            if (auto ok = exact(hold_hello_size); !ok) {
                return std::unexpected(ok.error());
            }
            HoldHello hello{.role = static_cast<HoldPeerRole>(r.u8().value_or(0))};
            const bool zero = detail::all_zero(r.bytes(3).value_or(std::span<const std::byte>{}));
            hello.replica_gen = r.le32().value_or(0);
            if (!zero) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            out = hello;
            break;
        }
        case detail::Shape::hello_ok: {
            if (auto ok = exact(hold_hello_ok_size); !ok) {
                return std::unexpected(ok.error());
            }
            HoldHelloOk hok{.block_size = r.le32().value_or(0)};
            const bool zero = r.le32().value_or(1) == 0;
            hok.capacity_blocks = r.le64().value_or(0);
            hok.commit_seq = r.le64().value_or(0);
            if (!zero) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            out = hok;
            break;
        }
        case detail::Shape::blocks: {
            auto d = detail::read_block_data(header, bytes);
            if (!d) {
                return std::unexpected(d.error());
            }
            out = *d;
            break;
        }
        case detail::Shape::repl_write: {
            if (bytes.size() < hold_repl_prefix_size) {
                return std::unexpected(DecodeError::bad_payload_size);
            }
            ReplWrite rw{};
            rw.seq = r.le64().value_or(0);
            rw.commit_seq = r.le64().value_or(0);
            rw.op = static_cast<ReplOp>(r.u8().value_or(0));
            if (!detail::all_zero(r.bytes(7).value_or(std::span<const std::byte>{}))) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            if (rw.op == ReplOp::write) {
                auto d = detail::read_block_data(header, r.rest());
                if (!d) {
                    return std::unexpected(d.error());
                }
                rw.data = *d;
            } else if (r.remaining() != 0) {
                return std::unexpected(DecodeError::bad_payload_size);
            }
            out = rw;
            break;
        }
        case detail::Shape::repl_ack:
            if (auto ok = exact(hold_seq_size); !ok) {
                return std::unexpected(ok.error());
            }
            out = ReplAck{.seq = r.le64().value_or(0)};
            break;
        case detail::Shape::intents: {
            if (bytes.size() < hold_intents_fixed_size) {
                return std::unexpected(DecodeError::bad_payload_size);
            }
            const std::size_t count = r.le32().value_or(0);
            if (r.le32().value_or(1) != 0) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            if (count > max_hold_intents) {
                return std::unexpected(DecodeError::too_many_entries);
            }
            if (auto ok = exact(hold_intents_fixed_size + (count * hold_intent_size)); !ok) {
                return std::unexpected(ok.error());
            }
            HoldIntents in;
            in.entries.resize(count);
            for (auto& e : in.entries) {
                e.seq = r.le64().value_or(0);
                e.lba = r.le64().value_or(0);
                e.blocks = r.le32().value_or(0);
                if (r.le32().value_or(1) != 0) {
                    return std::unexpected(DecodeError::reserved_not_zero);
                }
            }
            out = std::move(in);
            break;
        }
        case detail::Shape::sync_data: {
            if (bytes.size() < hold_seq_size) {
                return std::unexpected(DecodeError::bad_payload_size);
            }
            SyncData sd{};
            sd.seq = r.le64().value_or(0);
            auto d = detail::read_block_data(header, r.rest());
            if (!d) {
                return std::unexpected(d.error());
            }
            sd.data = *d;
            out = sd;
            break;
        }
        case detail::Shape::ping:
            if (auto ok = exact(hold_seq_size); !ok) {
                return std::unexpected(ok.error());
            }
            out = HoldPing{.commit_seq = r.le64().value_or(0)};
            break;
        case detail::Shape::redirect:
            if (auto ok = exact(hold_redirect_size); !ok) {
                return std::unexpected(ok.error());
            }
            out = HoldRedirect{.primary_server = r.le64().value_or(0),
                               .primary_epoch = r.le64().value_or(0)};
            break;
    }
    if (auto ok = detail::check_payload(header, out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Decodes one whole frame (header and payload in one buffer).
[[nodiscard]] inline auto decode_hold_frame(std::span<const std::byte> bytes)
    -> std::expected<HoldFrame, DecodeError> {
    if (bytes.size() < hold_header_size) {
        return std::unexpected(DecodeError::truncated);
    }
    auto h = decode_hold_header(bytes.first(hold_header_size));
    if (!h) {
        return std::unexpected(h.error());
    }
    const auto rest = bytes.subspan(hold_header_size);
    if (rest.size() < h->payload_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (rest.size() > h->payload_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    auto p = decode_hold_payload(*h, rest);
    if (!p) {
        return std::unexpected(p.error());
    }
    return HoldFrame{.header = *h, .payload = std::move(*p)};
}

// Encodes a header with the given payload length and its CRC, for a
// sender that writes the payload separately (no copy of block data).
// Checks the header rules, not the payload.
[[nodiscard]] inline auto encode_hold_header(HoldHeader h, std::size_t payload_len)
    -> std::expected<std::array<std::byte, hold_header_size>, DecodeError> {
    if (payload_len > max_hold_payload) {
        return std::unexpected(DecodeError::record_too_large);
    }
    h.payload_len = static_cast<std::uint32_t>(payload_len);
    if (auto ok = detail::check_hold_header(h); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> buf;
    buf.reserve(hold_header_size);
    wire::Writer w{buf};
    w.le32(hold_magic);
    w.u8(hold_version);
    w.u8(static_cast<std::uint8_t>(h.opcode));
    w.le16(h.flags);
    w.le32(h.payload_len);
    w.le16(static_cast<std::uint16_t>(h.status));
    w.le16(0);
    w.le64(h.request_id);
    w.le64(h.volume_id);
    w.le64(h.epoch);
    w.le64(h.attachment_id);
    w.le32(h.generation);
    w.le32(h.blocks);
    w.le64(h.lba);
    w.le32(0);
    w.le32(crc32c::of(buf));
    std::array<std::byte, hold_header_size> out{};
    std::ranges::copy(buf, out.begin());
    return out;
}

// Encodes a whole frame, enforcing every rule the decoders check. The
// header's payload_len is ignored and computed from the payload.
[[nodiscard]] inline auto encode_hold_frame(const HoldFrame& f)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    const std::size_t len = detail::payload_size(f.payload);
    auto header = encode_hold_header(f.header, len);
    if (!header) {
        return std::unexpected(header.error());
    }
    auto h = f.header;
    h.payload_len = static_cast<std::uint32_t>(len);
    if (auto ok = detail::check_payload(h, f.payload); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(hold_header_size + len);
    wire::Writer w{out};
    w.bytes(*header);
    const auto blocks = [&w](const BlockData& d) {
        w.bytes(d.crcs);
        w.bytes(d.data);
    };
    std::visit(
        [&]<typename T>(const T& v) {
            if constexpr (std::is_same_v<T, HoldHello>) {
                w.u8(static_cast<std::uint8_t>(v.role));
                w.bytes(std::array<std::byte, 3>{});
                w.le32(v.replica_gen);
            } else if constexpr (std::is_same_v<T, HoldHelloOk>) {
                w.le32(v.block_size);
                w.le32(0);
                w.le64(v.capacity_blocks);
                w.le64(v.commit_seq);
            } else if constexpr (std::is_same_v<T, BlockData>) {
                blocks(v);
            } else if constexpr (std::is_same_v<T, ReplWrite>) {
                w.le64(v.seq);
                w.le64(v.commit_seq);
                w.u8(static_cast<std::uint8_t>(v.op));
                w.bytes(std::array<std::byte, 7>{});
                blocks(v.data);
            } else if constexpr (std::is_same_v<T, ReplAck>) {
                w.le64(v.seq);
            } else if constexpr (std::is_same_v<T, HoldIntents>) {
                w.le32(static_cast<std::uint32_t>(v.entries.size()));
                w.le32(0);
                for (const auto& e : v.entries) {
                    w.le64(e.seq);
                    w.le64(e.lba);
                    w.le32(e.blocks);
                    w.le32(0);
                }
            } else if constexpr (std::is_same_v<T, SyncData>) {
                w.le64(v.seq);
                blocks(v.data);
            } else if constexpr (std::is_same_v<T, HoldPing>) {
                w.le64(v.commit_seq);
            } else if constexpr (std::is_same_v<T, HoldRedirect>) {
                w.le64(v.primary_server);
                w.le64(v.primary_epoch);
            }
        },
        f.payload);
    return out;
}

}  // namespace ak::proto
