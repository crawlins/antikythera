// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 1, 2 and 6: the virtio-blk
// function on the shared virtio core, driven through its BAR by a fake
// guest driver. The guest sees plaintext, the backend only ciphertext that
// matches AES-256-XTS with the logical block number as tweak, the key goes
// away on FLR and drop_key, and bad requests fail without touching the
// volume.

#define BOOST_TEST_MODULE virtio_blk_function_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

// Failure messages name the enums.
namespace ak::oar::blk {
auto operator<<(std::ostream& os, BlkConfigError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, KeyError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk
namespace ak::oar::virtio {
auto operator<<(std::ostream& os, AccessError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::virtio
// Boost.Test's customization point for types it cannot print itself.
namespace std {  // NOLINT(cert-dcl58-cpp): boost_test_print_type is found by ADL
auto boost_test_print_type(std::ostream& os, std::byte b) -> std::ostream& {
    return os << "0x" << std::hex << std::to_integer<unsigned>(b) << std::dec;
}
}  // namespace std

namespace blk = ak::oar::blk;
namespace vio = ak::oar::virtio;
using ak::test::Buffer;
using ak::test::GuestRam;
using ak::test::RecordingInterrupts;
using ak::test::unit_timeout_seconds;
using ak::test::VirtioDriver;
using blk::BlkConfigError;
using blk::BlkParams;
using blk::KeyError;
using blk::RequestType;
using blk::Status;
using blk::VolumeGeometry;

namespace {

constexpr std::uint64_t volume_sectors = 256;  // 128 KiB
constexpr std::uint32_t block_4k = 4096;
constexpr std::uint64_t sectors_per_4k = block_4k / blk::sector_size;
constexpr std::uint32_t test_seg_max = 4;
constexpr std::uint32_t test_max_transfer = 16 * 1024;
constexpr std::size_t half_key = blk::xts_key_size / 2;
constexpr std::uint8_t data_key_base = 0x01;
constexpr std::uint8_t tweak_key_base = 0x80;
constexpr std::byte status_canary{0xAA};
constexpr std::byte fill_canary{0xEE};
constexpr std::uint32_t unknown_type = 0xDEAD;
constexpr std::string_view test_serial = "oar-blk-test";
constexpr std::uint16_t queue0 = 0;
constexpr std::uint16_t queue1 = 1;

auto test_key() -> std::array<std::byte, blk::xts_key_size> {
    std::array<std::byte, blk::xts_key_size> k{};
    for (std::size_t i = 0; i < half_key; ++i) {
        k[i] = static_cast<std::byte>(data_key_base + i);
        k[half_key + i] = static_cast<std::byte>(tweak_key_base + i);
    }
    return k;
}

// Recognisable plaintext: byte i of sector s.
auto pattern(std::uint64_t first_sector, std::size_t bytes) -> std::vector<std::byte> {
    std::vector<std::byte> out(bytes);
    for (std::size_t i = 0; i < bytes; ++i) {
        const std::uint64_t sector = first_sector + (i / blk::sector_size);
        out[i] = static_cast<std::byte>((sector * 31U) + (i % blk::sector_size));
    }
    return out;
}

class MemoryBackend final : public blk::SyncBlockBackend {
public:
    explicit MemoryBackend(std::size_t bytes) : data(bytes, std::byte{0}) {}

    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override { return data.size(); }
    [[nodiscard]] auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, blk::BackendError> override {
        ++reads;
        if (fail) {
            return std::unexpected(blk::BackendError::io);
        }
        if (offset > data.size() || out.size() > data.size() - offset) {
            return std::unexpected(blk::BackendError::out_of_range);
        }
        std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(offset), out.size(), out.begin());
        return {};
    }
    [[nodiscard]] auto write(std::uint64_t offset, std::span<const std::byte> in)
        -> std::expected<void, blk::BackendError> override {
        ++writes;
        if (fail) {
            return std::unexpected(blk::BackendError::io);
        }
        if (offset > data.size() || in.size() > data.size() - offset) {
            return std::unexpected(blk::BackendError::out_of_range);
        }
        std::ranges::copy(in, data.begin() + static_cast<std::ptrdiff_t>(offset));
        return {};
    }
    [[nodiscard]] auto flush() -> std::expected<void, blk::BackendError> override {
        ++flushes;
        if (fail) {
            return std::unexpected(blk::BackendError::io);
        }
        return {};
    }

    std::vector<std::byte> data;
    bool fail{false};
    unsigned reads{0};
    unsigned writes{0};
    unsigned flushes{0};
};

auto params(std::uint32_t block_size = blk::sector_size, std::uint16_t queues = 1) -> BlkParams {
    return {.geometry = {.capacity_sectors = volume_sectors,
                         .logical_block_size = block_size,
                         .read_only = false,
                         .seg_max = test_seg_max,
                         .max_transfer_bytes = test_max_transfer},
            .num_queues = queues,
            .queue_size = ak::test::test_queue_size,
            .budget = ak::test::test_queue_size,
            .serial = test_serial};
}

// What the guest sees after one request.
struct Completion {
    std::byte status{status_canary};
    std::vector<std::byte> data;  // IN / GET_ID
    std::uint32_t used_len{0};
    bool completed{false};
};

// A function, its transport-side memory and interrupts, a backend to
// inspect, and a driver that has brought the device up.
class Rig {
public:
    explicit Rig(const BlkParams& p = params(), bool bring_up = true) {
        auto backend = std::make_unique<MemoryBackend>(volume_sectors * blk::sector_size);
        _backend = backend.get();
        auto fn = blk::VirtioBlkFunction::create(p, _ram.memory(), _irq, std::move(backend));
        BOOST_REQUIRE(fn);
        _fn = std::move(*fn);
        _driver.emplace(_ram, _fn->pci());
        _queues = p.num_queues;
        if (bring_up) {
            BOOST_REQUIRE(up());
        }
    }

    auto up() -> bool {
        std::vector<std::uint16_t> all(_queues);
        for (std::uint16_t i = 0; i < _queues; ++i) {
            all[i] = i;
        }
        return _driver->bring_up(offered(), all);
    }

    [[nodiscard]] auto offered() -> std::uint64_t {
        namespace cc = vio::common_cfg;
        std::uint64_t f = 0;
        for (std::uint32_t word = 0; word < 2; ++word) {
            BOOST_REQUIRE(
                _driver->common_write(cc::device_feature_select, ak::test::width32, word));
            const auto v = _driver->common_read(cc::device_feature, ak::test::width32);
            BOOST_REQUIRE(v);
            f |= *v << (32U * word);
        }
        return f;
    }

    auto deliver_key() -> void { BOOST_REQUIRE(_fn->deliver_key(test_key())); }

    // Posts one request (header, optional data, status) without notifying.
    // `out` is the data to write (OUT), `in_len` the room to read into.
    auto post(std::uint32_t type, std::uint64_t sector, std::span<const std::byte> out = {},
              std::uint32_t in_len = 0, std::uint16_t q = queue0) -> std::size_t {
        std::vector<Buffer> bufs{{.len = blk::header_size, .writable = false}};
        if (!out.empty()) {
            bufs.push_back({.len = static_cast<std::uint32_t>(out.size()), .writable = false});
        }
        if (in_len != 0) {
            bufs.push_back({.len = in_len, .writable = true});
        }
        bufs.push_back({.len = blk::status_size, .writable = true});
        std::vector<vio::Gpa> gpas;
        _driver->post(q, bufs, &gpas);
        std::vector<std::byte> hdr;
        ak::wire::Writer w{hdr};
        w.le32(type);
        w.le32(0);
        w.le64(sector);
        _ram.put_bytes(gpas[0], hdr);
        std::size_t next = 1;
        if (!out.empty()) {
            _ram.put_bytes(gpas[next++], out);
        }
        Pending p{.q = q, .data_gpa = 0, .data_len = in_len, .status_gpa = gpas.back()};
        if (in_len != 0) {
            p.data_gpa = gpas[next];
            const std::vector<std::byte> canary(in_len, fill_canary);
            _ram.put_bytes(p.data_gpa, canary);
        }
        _ram.put<std::byte>(p.status_gpa, status_canary);
        _pending.push_back(p);
        return _pending.size() - 1;
    }

    // Notifies and returns what the guest sees for request `id`.
    auto notify(std::uint16_t q = queue0) -> void { BOOST_REQUIRE(_driver->notify(q)); }

    [[nodiscard]] auto result(std::size_t id) const -> Completion {
        const Pending& p = _pending.at(id);
        Completion c;
        c.status = _ram.get<std::byte>(p.status_gpa);
        if (p.data_len != 0) {
            c.data = _ram.bytes(p.data_gpa, p.data_len);
        }
        const std::uint16_t done = _driver->used_idx(p.q);
        std::uint16_t nth = 0;
        for (std::size_t i = 0; i < id; ++i) {
            nth = static_cast<std::uint16_t>(nth + (_pending[i].q == p.q ? 1 : 0));
        }
        c.completed = nth < done;
        if (c.completed) {
            c.used_len = _driver->used_len(p.q, nth % ak::test::test_queue_size);
        }
        return c;
    }

    auto request(std::uint32_t type, std::uint64_t sector, std::span<const std::byte> out = {},
                 std::uint32_t in_len = 0, std::uint16_t q = queue0) -> Completion {
        const std::size_t id = post(type, sector, out, in_len, q);
        notify(q);
        return result(id);
    }
    auto write(std::uint64_t sector, std::span<const std::byte> data) -> Completion {
        return request(static_cast<std::uint32_t>(RequestType::out), sector, data);
    }
    auto read(std::uint64_t sector, std::uint32_t len, std::uint16_t q = queue0) -> Completion {
        return request(static_cast<std::uint32_t>(RequestType::in), sector, {}, len, q);
    }

    [[nodiscard]] auto fn() -> blk::VirtioBlkFunction& { return *_fn; }
    [[nodiscard]] auto backend() -> MemoryBackend& { return *_backend; }
    [[nodiscard]] auto driver() -> VirtioDriver& { return *_driver; }
    [[nodiscard]] auto ram() -> GuestRam& { return _ram; }
    [[nodiscard]] auto irq() -> RecordingInterrupts& { return _irq; }
    [[nodiscard]] auto status() -> std::uint8_t { return _fn->pci().status(); }

private:
    struct Pending {
        std::uint16_t q;
        vio::Gpa data_gpa;
        std::uint32_t data_len;
        vio::Gpa status_gpa;
    };

    GuestRam _ram;
    RecordingInterrupts _irq;
    MemoryBackend* _backend{nullptr};
    std::unique_ptr<blk::VirtioBlkFunction> _fn;
    std::optional<VirtioDriver> _driver;
    std::uint16_t _queues{1};
    std::vector<Pending> _pending;
};

auto ok() -> std::byte {
    return static_cast<std::byte>(Status::ok);
}
auto ioerr() -> std::byte {
    return static_cast<std::byte>(Status::ioerr);
}
auto unsupp() -> std::byte {
    return static_cast<std::byte>(Status::unsupp);
}

// The ciphertext an independent XtsCipher produces for `plain` at `unit`.
auto encrypt(std::uint64_t unit, std::size_t data_unit, std::span<const std::byte> plain)
    -> std::vector<std::byte> {
    const auto key = test_key();
    auto cipher = blk::XtsCipher::create(key, data_unit);
    BOOST_REQUIRE(cipher);
    std::vector<std::byte> out(plain.size());
    BOOST_REQUIRE(cipher->encrypt(unit, plain, out));
    return out;
}

auto backend_bytes(MemoryBackend& b, std::uint64_t sector, std::size_t len)
    -> std::vector<std::byte> {
    const auto at = b.data.begin() + static_cast<std::ptrdiff_t>(sector * blk::sector_size);
    return {at, at + static_cast<std::ptrdiff_t>(len)};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(creation)

BOOST_AUTO_TEST_CASE(rejects_bad_parameters, *boost::unit_test::timeout(unit_timeout_seconds)) {
    GuestRam ram;
    RecordingInterrupts irq;
    auto make = [&](const BlkParams& p, std::size_t backend_bytes = volume_sectors * 512)
        -> std::expected<std::unique_ptr<blk::VirtioBlkFunction>, BlkConfigError> {
        return blk::VirtioBlkFunction::create(p, ram.memory(), irq,
                                              std::make_unique<MemoryBackend>(backend_bytes));
    };
    BOOST_TEST(make(params()).has_value());

    auto p = params();
    p.geometry.logical_block_size = 1024;
    BOOST_TEST(make(p).error() == BlkConfigError::bad_geometry);

    p = params();
    p.geometry.seg_max = test_max_transfer / blk::sector_size;  // size_max 512 < one page
    BOOST_TEST(make(p).error() == BlkConfigError::bad_transfer);

    p = params();
    p.geometry.seg_max = 64;
    p.geometry.max_transfer_bytes = blk::max_bounce_bytes * 2;
    BOOST_TEST(make(p).error() == BlkConfigError::bad_transfer);

    p = params();
    p.num_queues = 0;
    BOOST_TEST(make(p).error() == BlkConfigError::bad_queues);

    p = params();
    p.queue_size = 3;
    BOOST_TEST(make(p).error() == BlkConfigError::bad_queues);

    p = params();
    p.budget = 0;
    BOOST_TEST(make(p).error() == BlkConfigError::bad_budget);

    p = params();
    p.serial = "123456789012345678901";
    BOOST_TEST(make(p).error() == BlkConfigError::serial_too_long);

    BOOST_TEST(make(params(), (volume_sectors * 512) - 1).error() ==
               BlkConfigError::backend_too_small);

    p = params();
    p.geometry.capacity_sectors = (std::uint64_t{1} << 62U);  // * 512 overflows
    BOOST_TEST(make(p).error() == BlkConfigError::backend_too_small);

    BOOST_TEST(blk::VirtioBlkFunction::create(params(), ram.memory(), irq, nullptr).error() ==
               BlkConfigError::backend_missing);
}

BOOST_AUTO_TEST_CASE(pci_identity_and_features, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{params(), false};
    BOOST_TEST(rig.fn().pci().identity().device_id == 0x1042);
    BOOST_TEST(rig.fn().pci().identity().class_code == 0x01);

    const std::uint64_t f = rig.offered();
    for (const unsigned bit :
         {vio::feature_version_1, vio::feature_access_platform, vio::feature_indirect_desc,
          vio::feature_event_idx, blk::feature_blk_size_max, blk::feature_blk_seg_max,
          blk::feature_blk_blk_size, blk::feature_blk_flush}) {
        BOOST_TEST((f & vio::feature_bit(bit)) != 0, "bit " << bit);
    }
    BOOST_TEST((f & vio::feature_bit(blk::feature_blk_ro)) == 0);
    BOOST_TEST((f & vio::feature_bit(blk::feature_blk_mq)) == 0);

    auto p = params(blk::sector_size, 2);
    p.geometry.read_only = true;
    Rig ro{p, false};
    const std::uint64_t g = ro.offered();
    BOOST_TEST((g & vio::feature_bit(blk::feature_blk_ro)) != 0);
    BOOST_TEST((g & vio::feature_bit(blk::feature_blk_mq)) != 0);
}

BOOST_AUTO_TEST_CASE(device_config_is_read_only, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{params(block_4k, 2)};
    auto& fn = rig.fn();
    BOOST_TEST(*fn.read_config(blk::blk_cfg::capacity, 8) == volume_sectors);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::capacity, 4) == volume_sectors);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::capacity + 4, 4) == 0U);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::size_max, 4) == test_max_transfer / test_seg_max);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::seg_max, 4) == test_seg_max);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::blk_size, 4) == block_4k);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::num_queues, 2) == 2U);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::writeback, 1) == 0U);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::geometry, 4) == 0U);

    // Through the BAR, the way the driver reads it.
    const auto via_bar =
        fn.pci().bar_read(vio::bar_layout::device_offset + blk::blk_cfg::blk_size, 4);
    BOOST_REQUIRE(via_bar);
    BOOST_TEST(*via_bar == block_4k);

    BOOST_TEST(fn.read_config(blk::blk_cfg::seg_max, 3).error() == vio::AccessError::bad_width);
    BOOST_TEST(fn.read_config(blk::blk_cfg::seg_max + 1, 4).error() == vio::AccessError::bad_width);
    BOOST_TEST(fn.read_config(blk::blk_cfg::size, 1).error() == vio::AccessError::bad_offset);
    BOOST_TEST(fn.read_config(32, 8).error() == vio::AccessError::bad_offset);

    BOOST_TEST(fn.write_config(blk::blk_cfg::capacity, 8, 1).error() ==
               vio::AccessError::read_only);
    BOOST_TEST(fn.write_config(blk::blk_cfg::writeback, 1, 1).error() ==
               vio::AccessError::read_only);
    BOOST_TEST(*fn.read_config(blk::blk_cfg::capacity, 8) == volume_sectors);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(data_path)

BOOST_AUTO_TEST_CASE(write_then_read_512, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    constexpr std::uint64_t sector = 10;
    constexpr std::size_t len = 2 * blk::sector_size;
    const auto plain = pattern(sector, len);

    const auto w = rig.write(sector, plain);
    BOOST_TEST(w.completed);
    BOOST_TEST(w.status == ok());
    BOOST_TEST(w.used_len == blk::status_size);

    // The backend holds exactly the XTS ciphertext, unit = sector.
    const auto stored = backend_bytes(rig.backend(), sector, len);
    BOOST_TEST(stored != plain);
    const auto expected = encrypt(sector, blk::data_unit_512, plain);
    BOOST_TEST(stored == expected, boost::test_tools::per_element());

    const auto r = rig.read(sector, len);
    BOOST_TEST(r.completed);
    BOOST_TEST(r.status == ok());
    BOOST_TEST(r.used_len == len + blk::status_size);
    BOOST_TEST(r.data == plain, boost::test_tools::per_element());
    BOOST_TEST(rig.fn().counters().completed == 2U);
}

BOOST_AUTO_TEST_CASE(write_then_read_4k, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{params(block_4k)};
    rig.deliver_key();
    constexpr std::uint64_t sector = 2 * sectors_per_4k;  // logical block 2
    constexpr std::size_t len = 2 * block_4k;
    const auto plain = pattern(sector, len);

    BOOST_TEST(rig.write(sector, plain).status == ok());
    const auto expected = encrypt(sector / sectors_per_4k, blk::data_unit_4k, plain);
    BOOST_TEST(backend_bytes(rig.backend(), sector, len) == expected,
               boost::test_tools::per_element());
    BOOST_TEST(rig.read(sector, len).data == plain, boost::test_tools::per_element());

    // Not on a logical block boundary: refused, volume untouched.
    const unsigned writes = rig.backend().writes;
    BOOST_TEST(rig.write(sector + 1, plain).status == ioerr());
    BOOST_TEST(rig.backend().writes == writes);
}

BOOST_AUTO_TEST_CASE(data_split_across_descriptors,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // One XTS unit split over descriptors of odd sizes, header sharing a
    // descriptor with data: the device must reassemble, not assume layout.
    Rig rig;
    rig.deliver_key();
    constexpr std::uint64_t sector = 4;
    constexpr std::size_t len = 2 * blk::sector_size;
    const auto plain = pattern(sector, len);
    constexpr std::uint32_t first = 16 + 300;  // header plus the start of the data

    std::vector<vio::Gpa> gpas;
    rig.driver().post(queue0,
                      {{.len = first, .writable = false},
                       {.len = static_cast<std::uint32_t>(len) - 300, .writable = false},
                       {.len = 1, .writable = true}},
                      &gpas);
    std::vector<std::byte> img;
    ak::wire::Writer w{img};
    w.le32(static_cast<std::uint32_t>(RequestType::out));
    w.le32(0);
    w.le64(sector);
    img.insert(img.end(), plain.begin(), plain.end());
    rig.ram().put_bytes(gpas[0], std::span{img}.first(first));
    rig.ram().put_bytes(gpas[1], std::span{img}.subspan(first));
    rig.notify();
    BOOST_TEST(rig.ram().get<std::byte>(gpas[2]) == ok());

    // Read it back into three uneven segments.
    gpas.clear();
    rig.driver().post(queue0,
                      {{.len = 16, .writable = false},
                       {.len = 100, .writable = true},
                       {.len = 700, .writable = true},
                       {.len = static_cast<std::uint32_t>(len) - 800 + 1, .writable = true}},
                      &gpas);
    std::vector<std::byte> hdr;
    ak::wire::Writer h{hdr};
    h.le32(static_cast<std::uint32_t>(RequestType::in));
    h.le32(0);
    h.le64(sector);
    rig.ram().put_bytes(gpas[0], hdr);
    rig.notify();
    std::vector<std::byte> back = rig.ram().bytes(gpas[1], 100);
    const auto mid = rig.ram().bytes(gpas[2], 700);
    const auto tail = rig.ram().bytes(gpas[3], len - 800 + 1);
    back.insert(back.end(), mid.begin(), mid.end());
    back.insert(back.end(), tail.begin(), tail.end() - 1);
    BOOST_TEST(tail.back() == ok());
    BOOST_TEST(back == plain, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(flush_and_get_id, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    const auto f = rig.request(static_cast<std::uint32_t>(RequestType::flush), 0);
    BOOST_TEST(f.status == ok());
    BOOST_TEST(rig.backend().flushes == 1U);

    const auto id =
        rig.request(static_cast<std::uint32_t>(RequestType::get_id), 0, {}, blk::id_bytes);
    BOOST_TEST(id.status == ok());
    BOOST_TEST(id.used_len == blk::id_bytes + blk::status_size);
    std::vector<std::byte> want(blk::id_bytes, std::byte{0});
    std::ranges::copy(std::as_bytes(std::span{test_serial}), want.begin());
    BOOST_TEST(id.data == want, boost::test_tools::per_element());

    // A shorter buffer gets a prefix; nothing past it is written.
    const auto short_id = rig.request(static_cast<std::uint32_t>(RequestType::get_id), 0, {}, 4);
    BOOST_TEST(short_id.status == ok());
    BOOST_TEST(short_id.used_len == 4U + blk::status_size);
    BOOST_TEST((short_id.data == std::vector<std::byte>(want.begin(), want.begin() + 4)));
}

BOOST_AUTO_TEST_CASE(bad_requests_fail_without_io,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    const auto plain = pattern(0, blk::sector_size);

    // Past the end, and wrapping around: IOERR, the volume untouched.
    BOOST_TEST(rig.write(volume_sectors, plain).status == ioerr());
    BOOST_TEST(rig.write(~std::uint64_t{0}, plain).status == ioerr());
    BOOST_TEST(rig.read(volume_sectors - 1, 2 * blk::sector_size).status == ioerr());
    // Not a whole block.
    BOOST_TEST(rig.write(0, std::span{plain}.first(100)).status == ioerr());
    // Unknown and unimplemented types: UNSUPP.
    BOOST_TEST(rig.request(unknown_type, 0).status == unsupp());
    BOOST_TEST(rig.request(static_cast<std::uint32_t>(RequestType::discard), 0, plain).status ==
               unsupp());
    BOOST_TEST(rig.backend().writes == 0U);
    BOOST_TEST(rig.backend().reads == 0U);
    BOOST_TEST(rig.fn().counters().failed_ioerr == 4U);
    BOOST_TEST(rig.fn().counters().failed_unsupp == 2U);
    // A failed request is still completed, so the driver gets its buffer.
    BOOST_TEST(rig.driver().used_idx(queue0) == 6U);
    BOOST_TEST((rig.status() & vio::status_device_needs_reset) == 0);
}

BOOST_AUTO_TEST_CASE(read_only_volume, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto p = params();
    p.geometry.read_only = true;
    Rig rig{p};
    rig.deliver_key();
    BOOST_TEST(rig.write(0, pattern(0, blk::sector_size)).status == ioerr());
    BOOST_TEST(rig.backend().writes == 0U);
    BOOST_TEST(rig.read(0, blk::sector_size).status == ok());
}

BOOST_AUTO_TEST_CASE(backend_failure_is_ioerr, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    rig.backend().fail = true;
    BOOST_TEST(rig.write(0, pattern(0, blk::sector_size)).status == ioerr());
    const auto r = rig.read(0, blk::sector_size);
    BOOST_TEST(r.status == ioerr());
    BOOST_TEST(r.used_len == blk::status_size);
    // Nothing (no stale plaintext, no ciphertext) reaches the guest buffer.
    BOOST_TEST((r.data == std::vector<std::byte>(blk::sector_size, fill_canary)));
    BOOST_TEST(rig.request(static_cast<std::uint32_t>(RequestType::flush), 0).status == ioerr());
}

BOOST_AUTO_TEST_CASE(multiple_queues, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{params(blk::sector_size, 2)};
    rig.deliver_key();
    const auto plain = pattern(20, blk::sector_size);
    BOOST_TEST(
        rig.request(static_cast<std::uint32_t>(RequestType::out), 20, plain, 0, queue1).status ==
        ok());
    const auto r = rig.read(20, blk::sector_size, queue0);
    BOOST_TEST(r.data == plain, boost::test_tools::per_element());
    BOOST_TEST(rig.driver().used_idx(queue1) == 1U);
    BOOST_TEST(rig.driver().used_idx(queue0) == 1U);
}

BOOST_AUTO_TEST_CASE(interrupts_and_budget, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto p = params();
    p.budget = 2;
    Rig rig{p};
    rig.deliver_key();
    for (int i = 0; i < 3; ++i) {
        rig.post(static_cast<std::uint32_t>(RequestType::flush), 0);
    }
    rig.irq().raised.clear();
    rig.notify();
    BOOST_TEST(rig.driver().used_idx(queue0) == 2U);
    BOOST_TEST((rig.irq().raised == std::vector<std::uint16_t>{queue0}));
    // EVENT_IDX is negotiated: the driver asks for an interrupt once the
    // used index passes 2 (used_event, after the avail ring entries).
    rig.ram().put<std::uint16_t>(
        VirtioDriver::avail_gpa(queue0) + ak::test::ring_header + (2U * ak::test::test_queue_size),
        2);
    BOOST_TEST(rig.fn().pci().poll() == false);  // the third is served, nothing left
    BOOST_TEST(rig.driver().used_idx(queue0) == 3U);
    BOOST_TEST(rig.irq().raised.size() == 2U);
    BOOST_TEST(rig.fn().pci().poll() == false);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(keys_and_resets)

BOOST_AUTO_TEST_CASE(no_key_means_no_volume_io, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    BOOST_TEST(!rig.fn().holds_key());
    BOOST_TEST(rig.write(0, pattern(0, blk::sector_size)).status == ioerr());
    BOOST_TEST(rig.read(0, blk::sector_size).status == ioerr());
    BOOST_TEST(rig.fn().counters().no_key == 2U);
    BOOST_TEST(rig.backend().writes == 0U);
    BOOST_TEST(rig.backend().reads == 0U);
    // Neither touches volume data.
    BOOST_TEST(rig.request(static_cast<std::uint32_t>(RequestType::flush), 0).status == ok());
    BOOST_TEST(
        rig.request(static_cast<std::uint32_t>(RequestType::get_id), 0, {}, blk::id_bytes).status ==
        ok());
}

BOOST_AUTO_TEST_CASE(key_delivery_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    BOOST_TEST(rig.fn().holds_key());
    BOOST_TEST(rig.fn().deliver_key(test_key()).error() == KeyError::occupied);
    BOOST_TEST(rig.fn().holds_key());

    rig.fn().drop_key();
    BOOST_TEST(!rig.fn().holds_key());
    BOOST_TEST(rig.write(0, pattern(0, blk::sector_size)).status == ioerr());
    rig.fn().drop_key();  // idempotent

    // Equal halves: refused, and nothing is left held.
    std::array<std::byte, blk::xts_key_size> weak{};
    weak.fill(std::byte{0x42});
    BOOST_TEST(rig.fn().deliver_key(weak).error() == KeyError::rejected);
    BOOST_TEST(!rig.fn().holds_key());
    BOOST_TEST(rig.write(0, pattern(0, blk::sector_size)).status == ioerr());

    rig.deliver_key();
    BOOST_TEST(rig.write(0, pattern(0, blk::sector_size)).status == ok());
}

BOOST_AUTO_TEST_CASE(flr_wipes_key_and_queues, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    const auto plain = pattern(8, blk::sector_size);
    BOOST_TEST(rig.write(8, plain).status == ok());

    rig.fn().function_reset();
    BOOST_TEST(!rig.fn().holds_key());
    BOOST_TEST(rig.status() == 0U);
    BOOST_TEST(rig.fn().pci().queue(queue0) == nullptr);
    BOOST_TEST(rig.fn().counters().function_resets == 1U);
    // The volume (ciphertext) is the backend's and survives.
    BOOST_TEST(backend_bytes(rig.backend(), 8, blk::sector_size) ==
               encrypt(8, blk::data_unit_512, plain));

    // A new driver gets a working device but no data until helm re-delivers.
    BOOST_REQUIRE(rig.up());
    BOOST_TEST(rig.read(8, blk::sector_size).status == ioerr());
    rig.deliver_key();
    BOOST_TEST(rig.read(8, blk::sector_size).data == plain, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(driver_reset_keeps_key, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    const auto plain = pattern(30, blk::sector_size);
    BOOST_TEST(rig.write(30, plain).status == ok());

    // The guest driver re-probes: device_status = 0, then a fresh bring-up.
    BOOST_REQUIRE(rig.driver().common_write(vio::common_cfg::device_status, ak::test::width8, 0));
    BOOST_TEST(rig.fn().pci().queue(queue0) == nullptr);
    BOOST_TEST(rig.fn().holds_key());
    BOOST_REQUIRE(rig.up());
    BOOST_TEST(rig.read(30, blk::sector_size).data == plain, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(awaiting_the_key_holds_requests,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    const auto plain = pattern(16, blk::sector_size);

    // The attach window: the VMM's open resets the function (FLR) after
    // prepare, before the key; the wait survives it.
    rig.fn().await_key();
    BOOST_TEST(rig.fn().awaiting_key());
    rig.fn().function_reset();
    BOOST_TEST(rig.fn().awaiting_key());
    BOOST_REQUIRE(rig.up());

    // The guest probes: its requests stay in the ring, not failed.
    const auto w = rig.post(static_cast<std::uint32_t>(RequestType::out), 16, plain);
    rig.notify();
    const auto r = rig.post(static_cast<std::uint32_t>(RequestType::in), 16, {}, blk::sector_size);
    rig.notify();
    BOOST_TEST(!rig.fn().pci().poll());
    BOOST_TEST(!rig.result(w).completed);
    BOOST_TEST(!rig.result(r).completed);
    BOOST_TEST(rig.fn().counters().no_key == 0U);
    BOOST_TEST(rig.backend().writes == 0U);

    // The key arrives: the next poll serves both, in order.
    rig.deliver_key();
    BOOST_TEST(!rig.fn().awaiting_key());
    static_cast<void>(rig.fn().pci().poll());
    BOOST_TEST(rig.result(w).status == ok());
    BOOST_TEST(rig.result(r).data == plain, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(drop_key_ends_the_wait, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.fn().await_key();
    const auto id = rig.post(static_cast<std::uint32_t>(RequestType::in), 0, {}, blk::sector_size);
    rig.notify();
    BOOST_TEST(!rig.result(id).completed);
    // helm gave up (cleaning): the held request now fails instead of hanging.
    rig.fn().drop_key();
    BOOST_TEST(!rig.fn().awaiting_key());
    rig.notify();
    BOOST_TEST(rig.result(id).status == ioerr());

    // With a key already held, await_key() changes nothing.
    rig.deliver_key();
    rig.fn().await_key();
    BOOST_TEST(!rig.fn().awaiting_key());
    BOOST_TEST(rig.write(0, pattern(0, blk::sector_size)).status == ok());
}

BOOST_AUTO_TEST_CASE(missing_status_byte_needs_reset,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    std::vector<vio::Gpa> gpas;
    rig.driver().post(queue0, {{.len = blk::header_size, .writable = false}}, &gpas);
    rig.irq().raised.clear();
    rig.notify();
    BOOST_TEST((rig.status() & vio::status_device_needs_reset) != 0);
    BOOST_TEST(rig.fn().counters().queue_errors == 1U);
    BOOST_TEST(rig.fn().pci().queue(queue0) == nullptr);
    // The config vector (num_queues) tells the driver.
    BOOST_TEST((rig.irq().raised == std::vector<std::uint16_t>{1}));
    // The key is not the guest's to remove.
    BOOST_TEST(rig.fn().holds_key());

    // Until the driver resets, kicks do nothing.
    rig.post(static_cast<std::uint32_t>(RequestType::flush), 0);
    rig.notify();
    BOOST_TEST(rig.driver().used_idx(queue0) == 0U);
    BOOST_REQUIRE(rig.up());
    BOOST_TEST(rig.request(static_cast<std::uint32_t>(RequestType::flush), 0).status == ok());
}

BOOST_AUTO_TEST_CASE(ring_error_needs_reset, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    // A descriptor pointing outside guest memory.
    rig.driver().put_desc(queue0, 0, 0x10, blk::header_size, 0, 0);
    rig.driver().publish(queue0, 0);
    rig.notify();
    BOOST_TEST((rig.status() & vio::status_device_needs_reset) != 0);
    BOOST_TEST(rig.fn().counters().queue_errors == 1U);
}

// The harbor L1 hang: while L1's own virtio_blk driver had the disk live,
// L1 reset or probed another function, the VMM unmapped that function's
// BAR window, and every unmap reached this function as DEVICE_NEEDS_RESET.
// Linux does not recover from that, so I/O stalled and boot never ended.
// An unmap that misses the rings must leave the driver working.
BOOST_AUTO_TEST_CASE(unrelated_unmap_keeps_io_flowing,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig;
    rig.deliver_key();
    const auto plain = pattern(40, blk::sector_size);
    BOOST_TEST(rig.write(40, plain).status == ok());

    constexpr vio::Gpa other_bar = 0xFE00'0000;
    constexpr std::uint64_t bar_size = vio::bar_layout::bar_size;
    rig.fn().pci().memory_changing(other_bar, bar_size);
    BOOST_TEST((rig.status() & vio::status_device_needs_reset) == 0);
    BOOST_TEST(rig.read(40, blk::sector_size).data == plain, boost::test_tools::per_element());

    // Unmapping the rings themselves still resets, as it must.
    rig.fn().pci().memory_changing(VirtioDriver::desc_gpa(queue0), 1);
    BOOST_TEST((rig.status() & vio::status_device_needs_reset) != 0);
}

BOOST_AUTO_TEST_SUITE_END()
