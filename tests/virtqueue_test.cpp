// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 1.4: the shared virtio core's
// guest memory translation and split virtqueue, driven from the driver side
// by writing rings into a fake guest RAM.

#define BOOST_TEST_MODULE virtqueue_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <ostream>
#include <string>
#include <vector>

#include "oar/virtio/guest_memory.hpp"
#include "oar/virtio/split_queue.hpp"
#include "test_support.hpp"

// Failure messages name the error.
namespace ak::oar::virtio {
auto boost_test_print_type(std::ostream& os, QueueError e) -> std::ostream& {
    return os << to_string(e);
}
auto boost_test_print_type(std::ostream& os, MemoryError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::virtio

namespace virtio = ak::oar::virtio;
using ak::test::unit_timeout_seconds;
using virtio::Gpa;
using virtio::MemoryError;
using virtio::QueueError;

namespace {

constexpr Gpa ram_base = 0x10000;
constexpr std::size_t ram_size = 0x10000;
constexpr Gpa desc_gpa = ram_base;
constexpr Gpa avail_gpa = ram_base + 0x1000;
constexpr Gpa used_gpa = ram_base + 0x2000;
constexpr Gpa indirect_gpa = ram_base + 0x3000;
constexpr Gpa data_gpa = ram_base + 0x4000;
constexpr Gpa outside_gpa = ram_base + ram_size;
constexpr std::uint16_t queue_size = 8;
constexpr std::uint32_t buf_len = 64;
constexpr std::size_t avail_ring_offset = 4;
constexpr std::size_t used_entry_size = 8;
constexpr std::size_t region_size = 0x100;

// Plays the guest driver: owns guest RAM and writes rings the way a
// virtio driver would, little-endian, at fixed guest addresses.
class Driver {
public:
    explicit Driver(std::uint16_t size = queue_size, bool event_idx = false, bool indirect = false)
        : _ram(ram_size) {
        BOOST_REQUIRE(_memory.add_region(ram_base, _ram));
        _config = {.size = size,
                   .desc = desc_gpa,
                   .driver = avail_gpa,
                   .device = used_gpa,
                   .event_idx = event_idx,
                   .indirect_desc = indirect};
    }

    [[nodiscard]] auto memory() const -> const virtio::GuestMemory& { return _memory; }
    [[nodiscard]] auto config() const -> const virtio::QueueConfig& { return _config; }
    [[nodiscard]] auto queue() -> virtio::SplitQueue {
        auto q = virtio::SplitQueue::create(_memory, _config);
        BOOST_REQUIRE(q);
        return std::move(*q);
    }

    auto put16(Gpa gpa, std::uint16_t v) -> void { put(gpa, v); }
    auto put32(Gpa gpa, std::uint32_t v) -> void { put(gpa, v); }
    auto put64(Gpa gpa, std::uint64_t v) -> void { put(gpa, v); }
    [[nodiscard]] auto get16(Gpa gpa) const -> std::uint16_t { return get<std::uint16_t>(gpa); }
    [[nodiscard]] auto get32(Gpa gpa) const -> std::uint32_t { return get<std::uint32_t>(gpa); }

    auto desc_at(Gpa table, std::uint16_t i, Gpa addr, std::uint32_t len, std::uint16_t flags,
                 std::uint16_t next = 0) -> void {
        const Gpa d = table + (virtio::descriptor_size * i);
        put64(d, addr);
        put32(d + 8, len);
        put16(d + 12, flags);
        put16(d + 14, next);
    }
    auto desc(std::uint16_t i, Gpa addr, std::uint32_t len, std::uint16_t flags,
              std::uint16_t next = 0) -> void {
        desc_at(desc_gpa, i, addr, len, flags, next);
    }

    // Puts `head` in the next available slot and bumps avail idx.
    auto publish(std::uint16_t head) -> void {
        put16(avail_gpa + avail_ring_offset + (2 * (_avail_idx % _config.size)), head);
        ++_avail_idx;
        put16(avail_gpa + 2, _avail_idx);
    }
    auto set_avail_idx(std::uint16_t idx) -> void {
        _avail_idx = idx;
        put16(avail_gpa + 2, idx);
    }

    [[nodiscard]] auto used_idx() const -> std::uint16_t { return get16(used_gpa + 2); }
    [[nodiscard]] auto used_id(std::uint16_t slot) const -> std::uint32_t {
        return get32(used_gpa + avail_ring_offset + (used_entry_size * slot));
    }
    [[nodiscard]] auto used_len(std::uint16_t slot) const -> std::uint32_t {
        return get32(used_gpa + avail_ring_offset + (used_entry_size * slot) + 4);
    }
    [[nodiscard]] auto used_flags() const -> std::uint16_t { return get16(used_gpa); }
    [[nodiscard]] auto avail_event() const -> std::uint16_t {
        return get16(used_gpa + avail_ring_offset + (used_entry_size * _config.size));
    }
    auto set_avail_flags(std::uint16_t f) -> void { put16(avail_gpa, f); }
    auto set_used_event(std::uint16_t v) -> void {
        put16(avail_gpa + avail_ring_offset + (2 * _config.size), v);
    }

    [[nodiscard]] auto host(Gpa gpa) const -> const std::byte* {
        return _ram.data() + (gpa - ram_base);
    }

private:
    template<typename T> auto put(Gpa gpa, T v) -> void {
        std::memcpy(_ram.data() + (gpa - ram_base), &v, sizeof v);  // little-endian host
    }
    template<typename T> [[nodiscard]] auto get(Gpa gpa) const -> T {
        T v{};
        std::memcpy(&v, _ram.data() + (gpa - ram_base), sizeof v);
        return v;
    }

    std::vector<std::byte> _ram;
    virtio::GuestMemory _memory;
    virtio::QueueConfig _config;
    std::uint16_t _avail_idx{0};
};

auto pop_error(virtio::SplitQueue& q) -> QueueError {
    auto r = q.pop();
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto pop_chain(virtio::SplitQueue& q) -> virtio::Chain {
    auto r = q.pop();
    BOOST_REQUIRE(r.has_value());
    BOOST_REQUIRE(r->has_value());
    return std::move(**r);
}

}  // namespace

// --- GuestMemory ---------------------------------------------------------

BOOST_AUTO_TEST_CASE(memory_translates_inside_a_region,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::byte> ram(region_size);
    virtio::GuestMemory m;
    BOOST_REQUIRE(m.add_region(ram_base, ram));
    auto s = m.writable(ram_base + 0x10, 0x20);
    BOOST_REQUIRE(s);
    BOOST_TEST(s->data() == ram.data() + 0x10);
    BOOST_TEST(s->size() == 0x20U);
    BOOST_TEST(m.readable(ram_base, region_size).has_value());
    BOOST_TEST(m.readable(ram_base + region_size, 0).has_value());
}

BOOST_AUTO_TEST_CASE(memory_refuses_ranges_outside_or_straddling,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::byte> a(region_size);
    std::vector<std::byte> b(region_size);
    virtio::GuestMemory m;
    BOOST_REQUIRE(m.add_region(ram_base, a));
    BOOST_REQUIRE(m.add_region(ram_base + region_size, b));  // adjacent
    BOOST_TEST(m.region_count() == 2U);
    BOOST_TEST(m.readable(ram_base - 1, 1).error() == MemoryError::unmapped);
    BOOST_TEST(m.readable(ram_base + region_size - 1, 2).error() == MemoryError::unmapped);
    BOOST_TEST(m.readable(ram_base + (2 * region_size), 1).error() == MemoryError::unmapped);
    BOOST_TEST(m.readable(std::numeric_limits<Gpa>::max(), 2).error() == MemoryError::unmapped);
    BOOST_TEST(m.readable(ram_base, std::numeric_limits<std::size_t>::max()).error() ==
               MemoryError::unmapped);
}

BOOST_AUTO_TEST_CASE(memory_regions_cannot_overlap_and_can_be_removed,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::byte> a(region_size);
    std::vector<std::byte> b(region_size);
    virtio::GuestMemory m;
    BOOST_REQUIRE(m.add_region(ram_base, a));
    BOOST_TEST(m.add_region(ram_base + region_size - 1, b).error() == MemoryError::overlap);
    BOOST_TEST(m.add_region(ram_base - 1, b).error() == MemoryError::overlap);
    BOOST_TEST(m.add_region(ram_base, std::span<std::byte>{}).error() == MemoryError::empty);
    BOOST_TEST(m.add_region(std::numeric_limits<Gpa>::max(), b).error() == MemoryError::unmapped);
    BOOST_TEST(m.remove_region(ram_base + 1).error() == MemoryError::not_found);
    BOOST_REQUIRE(m.remove_region(ram_base));
    BOOST_TEST(m.readable(ram_base, 1).error() == MemoryError::unmapped);
}

// --- SplitQueue: setup ---------------------------------------------------

BOOST_AUTO_TEST_CASE(create_checks_size_alignment_and_mapping,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    auto cfg = d.config();
    for (std::uint16_t bad : {std::uint16_t{0}, std::uint16_t{3}, std::uint16_t{0xFFFF}}) {
        cfg.size = bad;
        BOOST_TEST(virtio::SplitQueue::create(d.memory(), cfg).error() == QueueError::bad_size);
    }
    cfg = d.config();
    cfg.desc += 8;
    BOOST_TEST(virtio::SplitQueue::create(d.memory(), cfg).error() == QueueError::misaligned_ring);
    cfg = d.config();
    cfg.device += 2;
    BOOST_TEST(virtio::SplitQueue::create(d.memory(), cfg).error() == QueueError::misaligned_ring);
    cfg = d.config();
    cfg.driver = outside_gpa - 4;  // ring runs off the end of RAM
    BOOST_TEST(virtio::SplitQueue::create(d.memory(), cfg).error() == QueueError::ring_unmapped);
    cfg = d.config();
    cfg.size = virtio::max_queue_size;  // desc table larger than RAM
    BOOST_TEST(virtio::SplitQueue::create(d.memory(), cfg).error() == QueueError::ring_unmapped);
}

// --- SplitQueue: chains --------------------------------------------------

BOOST_AUTO_TEST_CASE(empty_queue_pops_nothing, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    auto q = d.queue();
    auto r = q.pop();
    BOOST_REQUIRE(r);
    BOOST_TEST(!r->has_value());
}

BOOST_AUTO_TEST_CASE(chain_maps_readable_then_writable_buffers,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, data_gpa, buf_len, virtio::desc_f_next, 3);
    d.desc(3, data_gpa + buf_len, buf_len / 2, virtio::desc_f_next | virtio::desc_f_write, 5);
    d.desc(5, data_gpa + (2 * buf_len), buf_len, virtio::desc_f_write);
    d.publish(0);
    auto q = d.queue();
    const auto c = pop_chain(q);
    BOOST_TEST(c.head == 0);
    BOOST_REQUIRE(c.readable.size() == 1U);
    BOOST_REQUIRE(c.writable.size() == 2U);
    BOOST_TEST(c.readable[0].data() == d.host(data_gpa));
    BOOST_TEST(c.writable[0].data() == d.host(data_gpa + buf_len));
    BOOST_TEST(c.writable[1].data() == d.host(data_gpa + (2 * buf_len)));
    BOOST_TEST(c.readable_bytes == buf_len);
    BOOST_TEST(c.writable_bytes == buf_len + (buf_len / 2));
    BOOST_TEST(q.in_flight() == 1U);

    BOOST_REQUIRE(q.push(c.head, buf_len));
    BOOST_TEST(d.used_idx() == 1);
    BOOST_TEST(d.used_id(0) == 0U);
    BOOST_TEST(d.used_len(0) == buf_len);
    BOOST_TEST(q.in_flight() == 0U);
}

BOOST_AUTO_TEST_CASE(indices_wrap_around_the_ring,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver fresh;
    auto q2 = fresh.queue();
    // Past 65535 so the free-running 16-bit indices wrap too.
    constexpr int rounds = 0x10000 + (2 * queue_size);
    for (int i = 0; i < rounds; ++i) {
        const auto head = static_cast<std::uint16_t>(i % queue_size);
        fresh.desc(head, data_gpa, buf_len, virtio::desc_f_write);
        fresh.publish(head);
        const auto c = pop_chain(q2);
        BOOST_REQUIRE(c.head == head);
        BOOST_REQUIRE(q2.push(c.head, buf_len));
        BOOST_REQUIRE(fresh.used_id(static_cast<std::uint16_t>(i % queue_size)) == head);
    }
    BOOST_TEST(fresh.used_idx() == static_cast<std::uint16_t>(rounds));
}

BOOST_AUTO_TEST_CASE(zero_length_buffers_are_allowed,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, outside_gpa, 0, virtio::desc_f_write);
    d.publish(0);
    auto q = d.queue();
    const auto c = pop_chain(q);
    BOOST_TEST(c.writable_bytes == 0U);
}

// --- SplitQueue: guest errors latch the queue broken ---------------------

BOOST_AUTO_TEST_CASE(readable_after_writable_breaks_the_queue,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, data_gpa, buf_len, virtio::desc_f_write | virtio::desc_f_next, 1);
    d.desc(1, data_gpa, buf_len, 0);
    d.publish(0);
    auto q = d.queue();
    BOOST_TEST(pop_error(q) == QueueError::readable_after_writable);
    BOOST_TEST(q.broken());
    BOOST_TEST(pop_error(q) == QueueError::broken);
    BOOST_TEST(q.push(0, 0).error() == QueueError::broken);
    BOOST_TEST(!q.needs_interrupt());
}

BOOST_AUTO_TEST_CASE(out_of_range_indices_are_refused,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    {
        Driver d;
        d.publish(queue_size);
        auto q = d.queue();
        BOOST_TEST(pop_error(q) == QueueError::head_out_of_range);
    }
    {
        Driver d;
        d.desc(0, data_gpa, buf_len, virtio::desc_f_next, queue_size);
        d.publish(0);
        auto q = d.queue();
        BOOST_TEST(pop_error(q) == QueueError::next_out_of_range);
    }
    {
        Driver d;
        d.set_avail_idx(queue_size + 1);
        auto q = d.queue();
        BOOST_TEST(pop_error(q) == QueueError::avail_index_jump);
    }
}

BOOST_AUTO_TEST_CASE(descriptor_loops_are_bounded,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, data_gpa, buf_len, virtio::desc_f_next, 1);
    d.desc(1, data_gpa, buf_len, virtio::desc_f_next, 0);
    d.publish(0);
    auto q = d.queue();
    BOOST_TEST(pop_error(q) == QueueError::chain_too_long);
}

BOOST_AUTO_TEST_CASE(buffers_must_be_in_guest_memory,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, outside_gpa - (buf_len / 2), buf_len, virtio::desc_f_write);
    d.publish(0);
    auto q = d.queue();
    BOOST_TEST(pop_error(q) == QueueError::buffer_unmapped);
}

BOOST_AUTO_TEST_CASE(a_head_in_flight_cannot_be_popped_again,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, data_gpa, buf_len, virtio::desc_f_write);
    d.publish(0);
    d.publish(0);
    auto q = d.queue();
    (void)pop_chain(q);
    BOOST_TEST(pop_error(q) == QueueError::head_in_flight);
}

// --- SplitQueue: indirect descriptors ------------------------------------

BOOST_AUTO_TEST_CASE(indirect_table_is_walked_when_negotiated,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d{queue_size, false, true};
    d.desc_at(indirect_gpa, 0, data_gpa, buf_len, virtio::desc_f_next, 2);
    d.desc_at(indirect_gpa, 2, data_gpa + buf_len, buf_len, virtio::desc_f_write);
    // The write flag on the indirect descriptor itself is ignored.
    d.desc(4, indirect_gpa, 3 * virtio::descriptor_size,
           virtio::desc_f_indirect | virtio::desc_f_write);
    d.publish(4);
    auto q = d.queue();
    const auto c = pop_chain(q);
    BOOST_TEST(c.head == 4);
    BOOST_TEST(c.readable.size() == 1U);
    BOOST_TEST(c.writable.size() == 1U);
    BOOST_TEST(c.writable[0].data() == d.host(data_gpa + buf_len));
}

BOOST_AUTO_TEST_CASE(indirect_rules_are_enforced,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    struct Case {
        bool negotiated;
        std::uint16_t flags;
        std::uint32_t len;
        std::uint16_t entry_flags;
        std::uint16_t entry_next;
        QueueError want;
    };
    const Case cases[] = {
        {false, virtio::desc_f_indirect, virtio::descriptor_size, 0, 0,
         QueueError::indirect_not_negotiated},
        {true, virtio::desc_f_indirect | virtio::desc_f_next, virtio::descriptor_size, 0, 0,
         QueueError::indirect_with_next},
        {true, virtio::desc_f_indirect, 0, 0, 0, QueueError::bad_indirect_length},
        {true, virtio::desc_f_indirect, virtio::descriptor_size + 1, 0, 0,
         QueueError::bad_indirect_length},
        {true, virtio::desc_f_indirect, virtio::descriptor_size, virtio::desc_f_indirect, 0,
         QueueError::nested_indirect},
        {true, virtio::desc_f_indirect, virtio::descriptor_size, virtio::desc_f_next, 1,
         QueueError::next_out_of_range},
        // The entry loops onto itself: bounded by the queue size.
        {true, virtio::desc_f_indirect, virtio::descriptor_size, virtio::desc_f_next, 0,
         QueueError::chain_too_long},
    };
    for (const auto& tc : cases) {
        Driver d{queue_size, false, tc.negotiated};
        d.desc_at(indirect_gpa, 0, data_gpa, buf_len, tc.entry_flags, tc.entry_next);
        d.desc(0, indirect_gpa, tc.len, tc.flags);
        d.publish(0);
        auto q = d.queue();
        BOOST_TEST(pop_error(q) == tc.want);
    }
}

BOOST_AUTO_TEST_CASE(indirect_table_counts_against_the_chain_budget,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d{queue_size, false, true};
    // queue_size entries plus the indirect descriptor: one too many.
    for (std::uint16_t i = 0; i < queue_size; ++i) {
        const bool last = i + 1 == queue_size;
        d.desc_at(indirect_gpa, i, data_gpa, buf_len, last ? 0 : virtio::desc_f_next,
                  static_cast<std::uint16_t>(i + 1));
    }
    d.desc(0, indirect_gpa, queue_size * virtio::descriptor_size, virtio::desc_f_indirect);
    d.publish(0);
    auto q = d.queue();
    BOOST_TEST(pop_error(q) == QueueError::chain_too_long);
}

// --- SplitQueue: push ----------------------------------------------------

BOOST_AUTO_TEST_CASE(push_accepts_only_popped_heads_within_capacity,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, data_gpa, buf_len, virtio::desc_f_write);
    d.publish(0);
    auto q = d.queue();
    BOOST_TEST(q.push(0, 0).error() == QueueError::unknown_head);
    BOOST_TEST(q.push(queue_size, 0).error() == QueueError::unknown_head);
    const auto c = pop_chain(q);
    BOOST_TEST(q.push(c.head, buf_len + 1).error() == QueueError::used_length_too_large);
    BOOST_REQUIRE(q.push(c.head, buf_len));
    BOOST_TEST(q.push(c.head, 0).error() == QueueError::unknown_head);
    // Device-side mistakes do not break the queue.
    BOOST_TEST(!q.broken());
}

// A device that parks a request keeps only its head and translates the
// chain again later; what the driver changed meanwhile is checked afresh.
BOOST_AUTO_TEST_CASE(rewalk_translates_an_in_flight_chain_again,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, data_gpa, buf_len, virtio::desc_f_next, 1);
    d.desc(1, data_gpa + buf_len, buf_len / 2, virtio::desc_f_write);
    d.publish(0);
    auto q = d.queue();
    BOOST_TEST(q.rewalk(0).error() == QueueError::unknown_head);  // not popped yet
    const auto first = pop_chain(q);

    auto again = q.rewalk(first.head);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(again->head == first.head);
    BOOST_TEST(again->readable[0].data() == d.host(data_gpa));
    BOOST_TEST(again->writable_bytes == buf_len / 2);
    BOOST_TEST(q.in_flight() == 1U);

    // The driver grew the writable buffer: push() may fill what it holds now.
    d.desc(1, data_gpa + buf_len, buf_len, virtio::desc_f_write);
    again = q.rewalk(first.head);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(again->writable_bytes == buf_len);
    BOOST_REQUIRE(q.push(first.head, buf_len));
    BOOST_TEST(q.rewalk(first.head).error() == QueueError::unknown_head);
    BOOST_TEST(q.rewalk(queue_size).error() == QueueError::unknown_head);
    BOOST_TEST(!q.broken());

    // A chain broken while in flight breaks the queue, as on pop().
    d.desc(2, data_gpa, buf_len, virtio::desc_f_write);
    d.publish(2);
    const auto second = pop_chain(q);
    d.desc(2, data_gpa, buf_len, virtio::desc_f_write | virtio::desc_f_next, 3);
    d.desc(3, data_gpa, buf_len, 0);  // readable after writable
    BOOST_TEST(q.rewalk(second.head).error() == QueueError::readable_after_writable);
    BOOST_TEST(q.broken());
    BOOST_TEST(q.rewalk(second.head).error() == QueueError::broken);
}

// --- SplitQueue: notification suppression --------------------------------

BOOST_AUTO_TEST_CASE(interrupts_follow_the_no_interrupt_flag,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d;
    d.desc(0, data_gpa, buf_len, virtio::desc_f_write);
    auto q = d.queue();
    BOOST_TEST(!q.needs_interrupt());  // nothing pushed
    d.publish(0);
    BOOST_REQUIRE(q.push(pop_chain(q).head, 1));
    BOOST_TEST(q.needs_interrupt());
    BOOST_TEST(!q.needs_interrupt());  // consumed

    d.set_avail_flags(virtio::avail_f_no_interrupt);
    d.publish(0);
    BOOST_REQUIRE(q.push(pop_chain(q).head, 1));
    BOOST_TEST(!q.needs_interrupt());
}

BOOST_AUTO_TEST_CASE(interrupts_follow_used_event_with_event_idx,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Driver d{queue_size, true};
    for (std::uint16_t i = 0; i < 3; ++i) {
        d.desc(i, data_gpa, buf_len, virtio::desc_f_write);
    }
    auto q = d.queue();
    // Driver asks to be interrupted once used idx passes 1 (i.e. reaches 2).
    d.set_used_event(1);
    d.publish(0);
    BOOST_REQUIRE(q.push(pop_chain(q).head, 1));  // used idx 1
    BOOST_TEST(!q.needs_interrupt());
    d.publish(1);
    BOOST_REQUIRE(q.push(pop_chain(q).head, 1));  // used idx 2
    BOOST_TEST(q.needs_interrupt());
    d.publish(2);
    BOOST_REQUIRE(q.push(pop_chain(q).head, 1));  // used idx 3, event still 1
    BOOST_TEST(!q.needs_interrupt());
}

BOOST_AUTO_TEST_CASE(notification_suppression_is_published_to_the_driver,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    {
        Driver d;
        auto q = d.queue();
        q.set_notifications(false);
        BOOST_TEST(d.used_flags() == virtio::used_f_no_notify);
        q.set_notifications(true);
        BOOST_TEST(d.used_flags() == 0);
    }
    {
        Driver d{queue_size, true};
        d.desc(0, data_gpa, buf_len, virtio::desc_f_write);
        d.publish(0);
        auto q = d.queue();
        (void)pop_chain(q);
        q.set_notifications(true);
        BOOST_TEST(d.avail_event() == 1);
    }
}

BOOST_AUTO_TEST_CASE(errors_have_names, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(std::string{virtio::to_string(QueueError::chain_too_long)} == "chain_too_long");
    BOOST_TEST(std::string{virtio::to_string(MemoryError::overlap)} == "overlap");
}
