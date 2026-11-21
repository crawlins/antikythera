// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the hold wire protocol decoder, header and every payload: an
// accepted frame must re-encode to identical bytes, decode the same way
// when streamed (header, then payload), and keep its block data inside the
// protocol's bounds. Checksums inside block data are only computed over,
// never trusted, so first_bad_block runs on whatever the input holds.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <variant>

#include "proto/hold_wire.hpp"

namespace proto = ak::proto;

namespace {

auto check_blocks(const proto::HoldHeader& h, const proto::BlockData& d) -> void {
    if (d.data.size() > proto::max_hold_data_bytes ||
        d.crcs.size() != std::size_t{h.blocks} * proto::hold_block_crc_size ||
        d.data.size() != std::size_t{h.blocks} * d.block_size ||
        proto::first_bad_block(d) > h.blocks) {
        std::abort();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto f = proto::decode_hold_frame(bytes);
    if (!f) {
        return 0;
    }
    auto again = proto::encode_hold_frame(*f);
    if (!again || !std::ranges::equal(*again, bytes)) {
        std::abort();
    }
    auto h = proto::decode_hold_header(bytes.first(proto::hold_header_size));
    auto p = h ? proto::decode_hold_payload(*h, bytes.subspan(proto::hold_header_size))
               : decltype(proto::decode_hold_payload(*h, {})){};
    if (!h || !p || !(*h == f->header) || !(*p == f->payload)) {
        std::abort();
    }
    if (const auto* d = std::get_if<proto::BlockData>(&f->payload)) {
        check_blocks(f->header, *d);
    } else if (const auto* rw = std::get_if<proto::ReplWrite>(&f->payload);
               rw != nullptr && rw->op == proto::ReplOp::write) {
        check_blocks(f->header, rw->data);
    } else if (const auto* sd = std::get_if<proto::SyncData>(&f->payload)) {
        check_blocks(f->header, sd->data);
    }
    return 0;
}
