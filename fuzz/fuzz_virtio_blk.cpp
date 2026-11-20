// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes VirtioBlkFunction as a hostile guest would drive it: the fuzzer
// owns guest RAM (rings, descriptors, request headers and data) and a
// script of BAR accesses, kicks, polls, key deliveries and resets. Checks
// that every backend access is a whole number of logical blocks inside the
// volume (Requirement 6.1), and that an FLR always leaves the function
// without a key (Requirements 1.2, 2.3). The backend's read_ready() answer
// is part of the script, so reads are parked and resumed (re-walking chains
// the guest may have changed meanwhile) at arbitrary points.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include "oar/blk/virtio_blk_function.hpp"
#include "oar/virtio/function.hpp"
#include "oar/virtio/guest_memory.hpp"

namespace {

namespace blk = ak::oar::blk;
namespace virtio = ak::oar::virtio;
namespace cc = virtio::common_cfg;

constexpr virtio::Gpa ram_base = 0x1000;
constexpr std::size_t ram_size = 0x8000;
constexpr std::uint16_t queue_size = 8;
// Driver-written areas first so short inputs reach them; request headers
// and data anywhere in RAM.
constexpr virtio::Gpa avail = ram_base;
constexpr virtio::Gpa desc = ram_base + 0x40;
constexpr virtio::Gpa used = ram_base + 0x7000;
constexpr std::size_t ram_image_max = 0x7000;  // not the used ring
constexpr std::uint64_t capacity_sectors = 64;
constexpr std::size_t header_bytes = 2;
constexpr std::size_t max_ops = 256;
constexpr std::uint8_t mode_event_idx = 0x01;
constexpr std::uint8_t mode_indirect = 0x02;
constexpr std::uint8_t mode_4k = 0x04;
constexpr std::uint8_t mode_read_only = 0x08;
constexpr std::uint32_t block_4k = 4096;
constexpr std::uint32_t seg_max = 2;
constexpr std::uint32_t max_transfer = 8192;
constexpr std::size_t half_key = blk::xts_key_size / 2;
constexpr std::size_t width8 = 1;
constexpr std::size_t width16 = 2;
constexpr std::size_t width32 = 4;
constexpr std::size_t width64 = 8;
constexpr std::array<std::size_t, 4> widths{width8, width16, width32, width64};

class NullInterrupts final : public virtio::InterruptSink {
public:
    auto raise(std::uint16_t /*vector*/) -> void override {}
};

// Aborts on any access the function should never make.
class CheckingBackend final : public blk::BlockBackend {
public:
    explicit CheckingBackend(std::uint32_t block) : _block{block}, _data(capacity_sectors * 512) {}

    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override {
        return _data.size();
    }
    [[nodiscard]] auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, blk::BackendError> override {
        check(offset, out.size());
        std::copy_n(_data.begin() + static_cast<std::ptrdiff_t>(offset), out.size(), out.begin());
        return {};
    }
    [[nodiscard]] auto read_ready(std::uint64_t offset, std::size_t len) -> bool override {
        check(offset, len);
        return ready;
    }
    [[nodiscard]] auto write(std::uint64_t offset, std::span<const std::byte> in)
        -> std::expected<void, blk::BackendError> override {
        check(offset, in.size());
        std::ranges::copy(in, _data.begin() + static_cast<std::ptrdiff_t>(offset));
        return {};
    }
    [[nodiscard]] auto flush() -> std::expected<void, blk::BackendError> override { return {}; }

    bool ready{true};

private:
    auto check(std::uint64_t offset, std::size_t len) const -> void {
        if (len == 0 || len % _block != 0 || offset % _block != 0 || offset > _data.size() ||
            len > _data.size() - offset || len > max_transfer) {
            std::abort();
        }
    }

    std::uint32_t _block;
    std::vector<std::byte> _data;
};

class Input {
public:
    explicit Input(std::span<const std::uint8_t> d) : _d{d} {}
    [[nodiscard]] auto empty() const -> bool { return _d.empty(); }
    auto u8() -> std::uint8_t {
        if (_d.empty()) {
            return 0;
        }
        const std::uint8_t v = _d[0];
        _d = _d.subspan(1);
        return v;
    }
    auto u16() -> std::uint16_t {
        return static_cast<std::uint16_t>(u8() | (static_cast<unsigned>(u8()) << 8U));
    }
    auto u32() -> std::uint32_t { return u16() | (static_cast<std::uint32_t>(u16()) << 16U); }

private:
    std::span<const std::uint8_t> _d;
};

auto bring_up(virtio::PciFunction& fn, std::uint64_t features) -> void {
    auto w = [&](std::uint32_t off, std::size_t width, std::uint64_t v) {
        static_cast<void>(fn.bar_write(virtio::bar_layout::common_offset + off, width, v));
    };
    const std::uint8_t s = virtio::status_acknowledge | virtio::status_driver;
    w(cc::device_status, width8, 0);
    w(cc::device_status, width8, virtio::status_acknowledge);
    w(cc::device_status, width8, s);
    w(cc::driver_feature_select, width32, 0);
    w(cc::driver_feature, width32, features & 0xFFFF'FFFFU);
    w(cc::driver_feature_select, width32, 1);
    w(cc::driver_feature, width32, features >> 32U);
    w(cc::device_status, width8, s | virtio::status_features_ok);
    w(cc::queue_select, width16, 0);
    w(cc::queue_size, width16, queue_size);
    w(cc::queue_msix_vector, width16, 0);
    w(cc::queue_desc, width64, desc);
    w(cc::queue_driver, width64, avail);
    w(cc::queue_device, width64, used);
    w(cc::queue_enable, width16, 1);
    w(cc::device_status, width8, s | virtio::status_features_ok | virtio::status_driver_ok);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < header_bytes) {
        return 0;
    }
    const std::uint8_t mode = data[0];
    const std::size_t image = std::min<std::size_t>(data[1] * 0x80U, ram_image_max);
    Input in{std::span{data, size}.subspan(header_bytes)};

    std::vector<std::byte> ram(ram_size);
    for (std::size_t i = 0; i < image && !in.empty(); ++i) {
        ram[i] = static_cast<std::byte>(in.u8());
    }
    virtio::GuestMemory memory;
    if (!memory.add_region(ram_base, ram)) {
        std::abort();
    }
    NullInterrupts irq;
    const std::uint32_t block = (mode & mode_4k) != 0 ? block_4k : blk::sector_size;
    auto owned = std::make_unique<CheckingBackend>(block);
    CheckingBackend* backend = owned.get();
    auto fn =
        blk::VirtioBlkFunction::create({.geometry = {.capacity_sectors = capacity_sectors,
                                                     .logical_block_size = block,
                                                     .read_only = (mode & mode_read_only) != 0,
                                                     .seg_max = seg_max,
                                                     .max_transfer_bytes = max_transfer},
                                        .num_queues = 1,
                                        .queue_size = queue_size,
                                        .budget = 4,
                                        .serial = "fuzz"},
                                       memory, irq, std::move(owned));
    if (!fn) {
        std::abort();
    }
    std::uint64_t features = virtio::feature_bit(virtio::feature_version_1) |
                             virtio::feature_bit(virtio::feature_access_platform) |
                             virtio::feature_bit(blk::feature_blk_flush);
    if ((mode & mode_event_idx) != 0) {
        features |= virtio::feature_bit(virtio::feature_event_idx);
    }
    if ((mode & mode_indirect) != 0) {
        features |= virtio::feature_bit(virtio::feature_indirect_desc);
    }
    blk::VirtioBlkFunction& dev = **fn;
    virtio::PciFunction& pci = dev.pci();
    bring_up(pci, features);

    std::array<std::byte, blk::xts_key_size> key{};
    for (std::size_t op = 0; op < max_ops && !in.empty(); ++op) {
        switch (in.u8() % 11) {
            case 0:
                static_cast<void>(pci.bar_write(virtio::bar_layout::notify_offset, width16, 0));
                break;
            case 1: {
                const std::uint32_t off = in.u16() % virtio::bar_layout::bar_size;
                static_cast<void>(pci.bar_read(off, widths[in.u8() % widths.size()]));
                break;
            }
            case 2: {
                const std::uint32_t off = in.u16() % virtio::bar_layout::bar_size;
                const std::size_t width = widths[in.u8() % widths.size()];
                std::uint64_t v = in.u32();
                if (width < width64) {
                    v &= (std::uint64_t{1} << (width * 8U)) - 1U;
                }
                static_cast<void>(pci.bar_write(off, width, v));
                break;
            }
            case 3:
                static_cast<void>(pci.poll());
                break;
            case 4:
                dev.function_reset();
                if (dev.holds_key()) {
                    std::abort();
                }
                break;
            case 5:
                bring_up(pci, features);
                break;
            case 6: {
                // Sometimes a weak key (equal halves), which must be refused.
                const std::uint8_t seed = in.u8();
                for (std::size_t i = 0; i < key.size(); ++i) {
                    key[i] = static_cast<std::byte>(
                        (seed & 1U) != 0 ? seed : seed + (i % half_key) + (i / half_key));
                }
                const bool had = dev.holds_key();
                const auto r = dev.deliver_key(key);
                if (had && r) {
                    std::abort();  // a second key without drop_key
                }
                break;
            }
            case 7:
                dev.drop_key();
                break;
            case 8:
                // The VMM unmapping something: often a range with no ring
                // (a BAR window), sometimes all of guest memory.
                if ((in.u8() & 1U) != 0) {
                    pci.memory_changing();
                } else {
                    pci.memory_changing(ram_base + in.u16(), in.u16());
                }
                break;
            case 9:
                backend->ready = !backend->ready;  // a miss starts, or its chunk arrives
                break;
            default: {
                // The guest rewrites a byte of its own RAM mid-run.
                const std::size_t at = in.u16() % ram_image_max;
                ram[at] = static_cast<std::byte>(in.u8());
                break;
            }
        }
    }
    return 0;
}
