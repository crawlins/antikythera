// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 3 (oar-blk task 14): the
// virtio-blk function over a backend that completes later. Requests park
// in slots and complete from the backend's completions, possibly out of
// order; a full queue waits for a slot; a reset abandons what is in flight
// without touching the new rings; guest memory is translated again at
// completion; and the key can go while a read is in the backend.

#define BOOST_TEST_MODULE virtio_blk_async_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "common/wire.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

namespace blk = ak::oar::blk;
namespace vio = ak::oar::virtio;
using ak::test::Buffer;
using ak::test::GuestRam;
using ak::test::RecordingInterrupts;
using ak::test::unit_timeout_seconds;
using ak::test::VirtioDriver;
using blk::RequestType;
using blk::Status;

namespace {

constexpr std::uint64_t volume_sectors = 64;
constexpr std::uint32_t max_transfer = 8 * 1024;
constexpr std::uint32_t seg_max = 2;
constexpr std::size_t half_key = blk::xts_key_size / 2;
constexpr std::byte canary{0xAA};
constexpr std::byte fill{0xEE};
constexpr std::uint16_t q0 = 0;

auto test_key() -> std::array<std::byte, blk::xts_key_size> {
    std::array<std::byte, blk::xts_key_size> k{};
    for (std::size_t i = 0; i < half_key; ++i) {
        k[i] = static_cast<std::byte>(1 + i);
        k[half_key + i] = static_cast<std::byte>(0x80 + i);
    }
    return k;
}

auto pattern(std::uint8_t seed, std::size_t n) -> std::vector<std::byte> {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::byte>(seed + (i * 7U));
    }
    return v;
}

// Holds every operation until the test completes it.
class AsyncBackend final : public blk::BlockBackend {
public:
    enum class Kind : std::uint8_t {
        read,
        write,
        flush
    };
    struct Op {
        Kind kind;
        std::uint64_t offset;
        std::span<std::byte> out;
        std::span<const std::byte> in;
        blk::BackendCompletion done;
    };

    explicit AsyncBackend(std::size_t bytes, int fd = -1) : data(bytes), _fd{fd} {}

    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override { return data.size(); }
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, blk::BackendCompletion done)
        -> void override {
        ops.push_back({Kind::read, offset, out, {}, std::move(done)});
    }
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in,
                      blk::BackendCompletion done) -> void override {
        ops.push_back({Kind::write, offset, {}, in, std::move(done)});
    }
    auto submit_flush(blk::BackendCompletion done) -> void override {
        ops.push_back({Kind::flush, 0, {}, {}, std::move(done)});
    }
    [[nodiscard]] auto poll() -> bool override {
        while (!ready.empty()) {
            auto [op, ok] = std::move(ready.front());
            ready.pop_front();
            run(std::move(op), ok);
        }
        return !ops.empty();
    }
    [[nodiscard]] auto wake_fd() const noexcept -> int override { return _fd; }

    // Marks op i (in submit order among those still held) ready for the
    // next poll().
    auto release(std::size_t i, bool ok = true) -> void {
        ready.emplace_back(std::move(ops.at(i)), ok);
        ops.erase(ops.begin() + static_cast<std::ptrdiff_t>(i));
    }

    std::vector<std::byte> data;
    std::vector<Op> ops;
    std::deque<std::pair<Op, bool>> ready;

private:
    auto run(Op op, bool ok) -> void {
        if (!ok) {
            op.done(std::unexpected(blk::BackendError::io));
            return;
        }
        const auto at = static_cast<std::ptrdiff_t>(op.offset);
        if (op.kind == Kind::read) {
            std::copy_n(data.begin() + at, op.out.size(), op.out.begin());
        } else if (op.kind == Kind::write) {
            std::ranges::copy(op.in, data.begin() + at);
        }
        op.done({});
    }

    int _fd;
};

struct Posted {
    std::uint16_t head{0};
    vio::Gpa data{0};
    std::uint32_t data_len{0};
    vio::Gpa status{0};
};

class Rig {
public:
    explicit Rig(std::uint16_t in_flight = 2, int wake_fd = -1) {
        auto backend = std::make_unique<AsyncBackend>(volume_sectors * blk::sector_size, wake_fd);
        _backend = backend.get();
        const blk::BlkParams p{.geometry = {.capacity_sectors = volume_sectors,
                                            .logical_block_size = blk::sector_size,
                                            .read_only = false,
                                            .seg_max = seg_max,
                                            .max_transfer_bytes = max_transfer},
                               .num_queues = 1,
                               .queue_size = ak::test::test_queue_size,
                               .budget = ak::test::test_queue_size,
                               .serial = "async",
                               .max_in_flight = in_flight};
        auto fn = blk::VirtioBlkFunction::create(p, _ram.memory(), _irq, std::move(backend));
        BOOST_REQUIRE(fn);
        _fn = std::move(*fn);
        _driver.emplace(_ram, _fn->pci());
        BOOST_REQUIRE(up());
        BOOST_REQUIRE(_fn->deliver_key(test_key()));
    }

    auto up() -> bool {
        namespace cc = vio::common_cfg;
        std::uint64_t f = 0;
        for (std::uint32_t word = 0; word < 2; ++word) {
            static_cast<void>(
                _driver->common_write(cc::device_feature_select, ak::test::width32, word));
            f |= _driver->common_read(cc::device_feature, ak::test::width32).value_or(0)
                 << (32U * word);
        }
        return _driver->bring_up(f, {q0});
    }

    auto post(RequestType type, std::uint64_t sector, std::span<const std::byte> out = {},
              std::uint32_t in_len = 0) -> Posted {
        std::vector<Buffer> bufs{{.len = blk::header_size, .writable = false}};
        if (!out.empty()) {
            bufs.push_back({.len = static_cast<std::uint32_t>(out.size()), .writable = false});
        }
        if (in_len != 0) {
            bufs.push_back({.len = in_len, .writable = true});
        }
        bufs.push_back({.len = blk::status_size, .writable = true});
        std::vector<vio::Gpa> gpas;
        Posted p;
        p.head = _driver->post(q0, bufs, &gpas);
        std::vector<std::byte> hdr;
        ak::wire::Writer w{hdr};
        w.le32(static_cast<std::uint32_t>(type));
        w.le32(0);
        w.le64(sector);
        _ram.put_bytes(gpas[0], hdr);
        if (!out.empty()) {
            _ram.put_bytes(gpas[1], out);
        }
        if (in_len != 0) {
            p.data = gpas[1];
            p.data_len = in_len;
            _ram.put_bytes(p.data, std::vector<std::byte>(in_len, fill));
        }
        p.status = gpas.back();
        _ram.put<std::byte>(p.status, canary);
        return p;
    }
    auto notify() -> void { BOOST_REQUIRE(_driver->notify(q0)); }

    [[nodiscard]] auto status(const Posted& p) const -> std::byte {
        return _ram.get<std::byte>(p.status);
    }
    [[nodiscard]] auto data(const Posted& p) const -> std::vector<std::byte> {
        return _ram.bytes(p.data, p.data_len);
    }
    [[nodiscard]] auto used() const -> std::uint16_t { return _driver->used_idx(q0); }
    [[nodiscard]] auto used_id(std::uint16_t n) const -> std::uint32_t {
        return _driver->used_id(q0, n % ak::test::test_queue_size);
    }

    [[nodiscard]] auto fn() -> blk::VirtioBlkFunction& { return *_fn; }
    [[nodiscard]] auto backend() -> AsyncBackend& { return *_backend; }
    [[nodiscard]] auto ram() -> GuestRam& { return _ram; }
    [[nodiscard]] auto driver() -> VirtioDriver& { return *_driver; }
    auto destroy() -> void {
        _backend = nullptr;
        _fn.reset();
    }

private:
    GuestRam _ram;
    RecordingInterrupts _irq;
    AsyncBackend* _backend{nullptr};
    std::unique_ptr<blk::VirtioBlkFunction> _fn;
    std::optional<VirtioDriver> _driver;
};

auto ok() -> std::byte {
    return static_cast<std::byte>(Status::ok);
}
auto ioerr() -> std::byte {
    return static_cast<std::byte>(Status::ioerr);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(async_backend, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(requests_park_until_their_completion) {
    Rig rig;
    const auto plain = pattern(3, blk::sector_size);
    const auto w = rig.post(RequestType::out, 2, plain);
    rig.notify();
    BOOST_TEST(rig.backend().ops.size() == 1U);
    BOOST_TEST(rig.used() == 0);  // parked: nothing completed yet
    BOOST_TEST((rig.status(w) == canary));
    BOOST_TEST(rig.fn().in_flight() == 1U);
    // In flight with no wake descriptor: poll() keeps the loop polling.
    BOOST_TEST(rig.fn().poll());

    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST(rig.used() == 1);
    BOOST_TEST((rig.status(w) == ok()));
    BOOST_TEST(rig.fn().in_flight() == 0U);
    BOOST_TEST(rig.fn().counters().parked == 1U);
    BOOST_TEST(!rig.fn().poll());

    // And the ciphertext reads back as the plaintext.
    const auto r = rig.post(RequestType::in, 2, {}, blk::sector_size);
    rig.notify();
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST((rig.status(r) == ok()));
    BOOST_TEST((rig.data(r) == plain));
    BOOST_TEST(rig.fn().counters().completed == 2U);
}

BOOST_AUTO_TEST_CASE(completions_may_come_out_of_order) {
    Rig rig;
    const auto a = rig.post(RequestType::in, 0, {}, blk::sector_size);
    const auto b = rig.post(RequestType::flush, 0);
    rig.notify();
    BOOST_TEST(rig.backend().ops.size() == 2U);
    rig.backend().release(1);  // the flush first
    static_cast<void>(rig.fn().poll());
    BOOST_TEST(rig.used() == 1);
    BOOST_TEST(rig.used_id(0) == b.head);
    BOOST_TEST((rig.status(b) == ok()));
    BOOST_TEST((rig.status(a) == canary));
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST(rig.used() == 2);
    BOOST_TEST(rig.used_id(1) == a.head);
    BOOST_TEST((rig.status(a) == ok()));
}

BOOST_AUTO_TEST_CASE(a_full_queue_waits_for_a_slot) {
    Rig rig{1};
    const auto a = rig.post(RequestType::flush, 0);
    const auto b = rig.post(RequestType::flush, 0);
    rig.notify();
    BOOST_TEST(rig.backend().ops.size() == 1U);  // b stays in the ring
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());  // a completes, the freed slot takes b
    BOOST_TEST((rig.status(a) == ok()));
    BOOST_TEST(rig.backend().ops.size() == 1U);
    BOOST_TEST((rig.status(b) == canary));
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST((rig.status(b) == ok()));
    BOOST_TEST(rig.used() == 2);
}

BOOST_AUTO_TEST_CASE(failures_report_ioerr_and_leave_the_data_alone) {
    Rig rig;
    const auto r = rig.post(RequestType::in, 0, {}, blk::sector_size);
    rig.notify();
    rig.backend().release(0, false);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST((rig.status(r) == ioerr()));
    BOOST_TEST((rig.data(r) == std::vector<std::byte>(blk::sector_size, fill)));
    BOOST_TEST(rig.driver().used_len(q0, 0) == blk::status_size);
    BOOST_TEST(rig.fn().counters().failed_ioerr == 1U);
}

BOOST_AUTO_TEST_CASE(a_dropped_key_fails_a_read_in_flight) {
    Rig rig;
    const auto r = rig.post(RequestType::in, 0, {}, blk::sector_size);
    rig.notify();
    rig.fn().drop_key();
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST((rig.status(r) == ioerr()));
    BOOST_TEST((rig.data(r) == std::vector<std::byte>(blk::sector_size, fill)));
}

BOOST_AUTO_TEST_CASE(a_reset_abandons_what_is_in_flight) {
    Rig rig;
    const auto plain = pattern(9, blk::sector_size);
    const auto w = rig.post(RequestType::out, 4, plain);
    rig.notify();
    rig.fn().function_reset();
    BOOST_TEST(rig.fn().counters().abandoned == 1U);
    // The write still lands whole: its buffer was not wiped underneath it.
    BOOST_REQUIRE(rig.up());
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST((rig.status(w) == canary));  // nothing written into guest memory
    BOOST_TEST(rig.used() == 0);            // nor onto the new ring
    BOOST_TEST(rig.fn().in_flight() == 0U);
    BOOST_TEST(!rig.fn().poll());

    // The new rings work, the key is gone after FLR, and the block holds
    // the abandoned write's ciphertext.
    BOOST_REQUIRE(rig.fn().deliver_key(test_key()));
    const auto r = rig.post(RequestType::in, 4, {}, blk::sector_size);
    rig.notify();
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST((rig.status(r) == ok()));
    BOOST_TEST((rig.data(r) == plain));
}

BOOST_AUTO_TEST_CASE(memory_removed_under_a_parked_request_needs_reset) {
    Rig rig;
    const auto r = rig.post(RequestType::in, 0, {}, blk::sector_size);
    rig.notify();
    // The VMM removes guest memory that holds no ring (the function stays
    // live) while the read is in the backend.
    rig.fn().pci().memory_changing(r.data, r.data_len);
    BOOST_TEST((rig.fn().pci().status() & vio::status_device_needs_reset) == 0);
    BOOST_REQUIRE(rig.ram().memory().remove_region(ak::test::guest_ram_base));
    rig.backend().release(0);
    static_cast<void>(rig.fn().poll());
    BOOST_TEST(rig.fn().counters().queue_errors == 1U);
}

BOOST_AUTO_TEST_CASE(a_wake_descriptor_lets_the_loop_sleep) {
    Rig rig{2, 42};
    BOOST_TEST(rig.fn().wake_fd() == 42);
    static_cast<void>(rig.post(RequestType::flush, 0));
    rig.notify();
    BOOST_TEST(rig.fn().in_flight() == 1U);
    BOOST_TEST(!rig.fn().poll());  // the loop waits on the descriptor instead
}

BOOST_AUTO_TEST_CASE(destruction_with_requests_in_flight) {
    Rig rig;
    static_cast<void>(rig.post(RequestType::in, 0, {}, blk::sector_size));
    static_cast<void>(rig.post(RequestType::flush, 0));
    rig.notify();
    BOOST_TEST(rig.fn().in_flight() == 2U);
    rig.destroy();  // the backend drops its completions; nothing runs after
}

BOOST_AUTO_TEST_CASE(max_in_flight_is_checked) {
    GuestRam ram;
    RecordingInterrupts irq;
    blk::BlkParams p{.geometry = {.capacity_sectors = volume_sectors,
                                  .logical_block_size = blk::sector_size,
                                  .read_only = false,
                                  .seg_max = seg_max,
                                  .max_transfer_bytes = max_transfer},
                     .num_queues = 1,
                     .queue_size = ak::test::test_queue_size,
                     .budget = 1,
                     .serial = "x",
                     .max_in_flight = 0};
    for (const std::uint16_t n : {std::uint16_t{0}, std::uint16_t{ak::test::test_queue_size + 1}}) {
        p.max_in_flight = n;
        auto fn = blk::VirtioBlkFunction::create(
            p, ram.memory(), irq, std::make_unique<AsyncBackend>(volume_sectors * 512));
        BOOST_REQUIRE(!fn);
        BOOST_TEST((fn.error() == blk::BlkConfigError::bad_in_flight));
    }
}

BOOST_AUTO_TEST_SUITE_END()
