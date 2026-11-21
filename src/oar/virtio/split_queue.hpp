// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The device side of a virtio 1.x split virtqueue (virtio spec 2.7), shared
// by every oar device (.kiro/specs/oar-net-data-plane/ Requirement 1.4).
//
// Everything in the rings is written by the guest and may change while we
// read it, so the rules are:
//
//   - every descriptor, ring entry and index is copied out of guest memory
//     once, then validated, then used; nothing is re-read after a check;
//   - every buffer address goes through GuestMemory, so a descriptor can
//     only name memory the transport registered for this device;
//   - a chain may visit at most `size` descriptors in total, direct and
//     indirect together (spec 2.7.5.3.1), which also bounds loops;
//   - readable descriptors come before writable ones (spec 2.7.4.2), an
//     indirect table holds no indirect descriptor and is a whole number of
//     descriptors, and INDIRECT never comes with NEXT;
//   - a head the device already holds cannot be popped again, and push()
//     accepts only heads it popped, with no more bytes than the chain had
//     room for.
//
// The first structural error latches the queue broken: the guest has
// violated the spec and the transport should set DEVICE_NEEDS_RESET. Every
// later call returns QueueError::broken until the queue is rebuilt.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

#include "oar/virtio/guest_memory.hpp"

namespace ak::oar::virtio {

inline constexpr std::uint16_t max_queue_size = 32768;  // spec 2.7: Queue Size <= 32768
inline constexpr std::size_t descriptor_size = 16;
inline constexpr std::size_t desc_table_align = 16;
inline constexpr std::size_t avail_ring_align = 2;
inline constexpr std::size_t used_ring_align = 4;

inline constexpr std::uint16_t desc_f_next = 1;
inline constexpr std::uint16_t desc_f_write = 2;
inline constexpr std::uint16_t desc_f_indirect = 4;
inline constexpr std::uint16_t avail_f_no_interrupt = 1;
inline constexpr std::uint16_t used_f_no_notify = 1;

// Bytes of each ring area for a queue of `size` entries, including the
// event-index trailer (always counted: a driver may lay it out regardless).
[[nodiscard]] constexpr auto desc_table_bytes(std::uint16_t size) noexcept -> std::size_t {
    return descriptor_size * size;
}
[[nodiscard]] constexpr auto avail_ring_bytes(std::uint16_t size) noexcept -> std::size_t {
    return 6 + (2 * std::size_t{size});  // flags, idx, ring[size], used_event
}
[[nodiscard]] constexpr auto used_ring_bytes(std::uint16_t size) noexcept -> std::size_t {
    return 6 + (8 * std::size_t{size});  // flags, idx, ring[size]{id,len}, avail_event
}

// What the driver programmed through the common configuration
// (pci.hpp CommonConfig::queue), plus the features that change ring use.
struct QueueConfig {
    std::uint16_t size{0};
    Gpa desc{0};
    Gpa driver{0};              // available ring
    Gpa device{0};              // used ring
    bool event_idx{false};      // VIRTIO_F_EVENT_IDX negotiated
    bool indirect_desc{false};  // VIRTIO_F_INDIRECT_DESC negotiated
};

enum class QueueError : std::uint8_t {
    bad_size,                 // size is 0, not a power of two, or > 32768
    misaligned_ring,          // a ring address breaks spec 2.7 alignment
    ring_unmapped,            // a ring area is not inside guest memory
    avail_index_jump,         // avail idx moved more than size past what we consumed
    head_out_of_range,        // avail ring entry >= size
    head_in_flight,           // head the device already holds
    next_out_of_range,        // NEXT index outside the table it belongs to
    chain_too_long,           // more than size descriptors (or a loop)
    buffer_unmapped,          // a descriptor's buffer is not inside guest memory
    readable_after_writable,  // device-readable descriptor after a writable one
    indirect_not_negotiated,  // INDIRECT flag without VIRTIO_F_INDIRECT_DESC
    indirect_with_next,       // INDIRECT and NEXT both set
    nested_indirect,          // INDIRECT inside an indirect table
    bad_indirect_length,      // indirect table empty or not a multiple of 16 bytes
    unknown_head,             // push() of a head that is not in flight
    used_length_too_large,    // push() claims more bytes than the chain could take
    broken,                   // an earlier error latched the queue
};

[[nodiscard]] auto to_string(QueueError e) noexcept -> const char*;

// One available buffer: the device reads `readable` in order, then writes
// `writable` in order. The spans alias guest memory.
struct Chain {
    std::uint16_t head{0};
    std::vector<std::span<const std::byte>> readable;
    std::vector<std::span<std::byte>> writable;
    std::uint64_t readable_bytes{0};
    std::uint64_t writable_bytes{0};
};

class SplitQueue {
public:
    // Validates the configuration and resolves the three ring areas.
    [[nodiscard]] static auto create(const GuestMemory& memory, const QueueConfig& config)
        -> std::expected<SplitQueue, QueueError>;

    // Next available chain, or nullopt when the driver has posted nothing new.
    [[nodiscard]] auto pop() -> std::expected<std::optional<Chain>, QueueError>;

    // A popped chain again, translated afresh, for a device that kept only
    // the head of a request it could not finish at once (spans do not
    // survive between calls: memory_changing may unmap them). The chain is
    // checked as on pop(); a structural error latches the queue broken. The
    // head must be in flight, else unknown_head (a device bug, not latched).
    [[nodiscard]] auto rewalk(std::uint16_t head) -> std::expected<Chain, QueueError>;

    // Returns a popped chain to the driver with `written` bytes filled in.
    [[nodiscard]] auto push(std::uint16_t head, std::uint32_t written)
        -> std::expected<void, QueueError>;

    // Whether the driver wants an interrupt for what push() published since
    // the last call (used_event with EVENT_IDX, else the NO_INTERRUPT flag).
    // Call after a batch of pushes; it consumes the batch.
    [[nodiscard]] auto needs_interrupt() -> bool;

    // Asks the driver to notify (true) or not bother (false) on new buffers.
    // After enabling, call pop() again: buffers posted before the driver saw
    // the change produce no notification.
    auto set_notifications(bool enabled) -> void;

    [[nodiscard]] auto size() const noexcept -> std::uint16_t { return _config.size; }
    [[nodiscard]] auto broken() const noexcept -> bool { return _broken; }
    [[nodiscard]] auto in_flight() const noexcept -> std::size_t { return _in_flight_count; }

private:
    struct Descriptor {
        Gpa addr;
        std::uint32_t len;
        std::uint16_t flags;
        std::uint16_t next;
    };

    SplitQueue(const GuestMemory& memory, const QueueConfig& config, std::span<std::byte> desc,
               std::span<std::byte> avail, std::span<std::byte> used);

    auto fail(QueueError e) -> std::unexpected<QueueError>;
    auto walk(std::uint16_t head) -> std::expected<Chain, QueueError>;
    auto add_buffer(Chain& chain, const Descriptor& d, bool& seen_writable)
        -> std::expected<void, QueueError>;

    const GuestMemory* _memory;
    QueueConfig _config;
    std::span<std::byte> _desc;
    std::span<std::byte> _avail;
    std::span<std::byte> _used;
    std::uint16_t _last_avail{0};
    std::uint16_t _used_idx{0};
    std::uint16_t _signalled_used{0};
    std::vector<std::uint64_t> _capacity;  // per in-flight head: writable bytes
    std::vector<bool> _in_flight;
    std::size_t _in_flight_count{0};
    bool _broken{false};
};

}  // namespace ak::oar::virtio
