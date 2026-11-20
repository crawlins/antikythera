// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/virtio/split_queue.hpp"

#include <atomic>
#include <bit>
#include <cstring>

#include "common/wire.hpp"

namespace ak::oar::virtio {

namespace {

// Ring layout offsets (spec 2.7.6 and 2.7.8).
constexpr std::size_t ring_flags_offset = 0;
constexpr std::size_t ring_idx_offset = 2;
constexpr std::size_t ring_entries_offset = 4;
constexpr std::size_t avail_entry_size = 2;
constexpr std::size_t used_entry_size = 8;
constexpr std::size_t used_entry_len_offset = 4;

auto load16(std::span<const std::byte> area, std::size_t offset) noexcept -> std::uint16_t {
    std::uint16_t v{};
    std::memcpy(&v, area.data() + offset, sizeof v);
    return std::endian::native == std::endian::little ? v : std::byteswap(v);
}

auto store16(std::span<std::byte> area, std::size_t offset, std::uint16_t v) noexcept -> void {
    if constexpr (std::endian::native != std::endian::little) {
        v = std::byteswap(v);
    }
    std::memcpy(area.data() + offset, &v, sizeof v);
}

auto store32(std::span<std::byte> area, std::size_t offset, std::uint32_t v) noexcept -> void {
    if constexpr (std::endian::native != std::endian::little) {
        v = std::byteswap(v);
    }
    std::memcpy(area.data() + offset, &v, sizeof v);
}

// The event-index test of spec 2.7.7.2 (vring_need_event): has the used
// index crossed `event` in the window (old, new]?
constexpr auto need_event(std::uint16_t event, std::uint16_t new_idx,
                          std::uint16_t old_idx) noexcept -> bool {
    return static_cast<std::uint16_t>(new_idx - event - 1) <
           static_cast<std::uint16_t>(new_idx - old_idx);
}

}  // namespace

auto to_string(QueueError e) noexcept -> const char* {
    switch (e) {
        case QueueError::bad_size:
            return "bad_size";
        case QueueError::misaligned_ring:
            return "misaligned_ring";
        case QueueError::ring_unmapped:
            return "ring_unmapped";
        case QueueError::avail_index_jump:
            return "avail_index_jump";
        case QueueError::head_out_of_range:
            return "head_out_of_range";
        case QueueError::head_in_flight:
            return "head_in_flight";
        case QueueError::next_out_of_range:
            return "next_out_of_range";
        case QueueError::chain_too_long:
            return "chain_too_long";
        case QueueError::buffer_unmapped:
            return "buffer_unmapped";
        case QueueError::readable_after_writable:
            return "readable_after_writable";
        case QueueError::indirect_not_negotiated:
            return "indirect_not_negotiated";
        case QueueError::indirect_with_next:
            return "indirect_with_next";
        case QueueError::nested_indirect:
            return "nested_indirect";
        case QueueError::bad_indirect_length:
            return "bad_indirect_length";
        case QueueError::unknown_head:
            return "unknown_head";
        case QueueError::used_length_too_large:
            return "used_length_too_large";
        case QueueError::broken:
            return "broken";
    }
    return "unknown";
}

auto SplitQueue::create(const GuestMemory& memory, const QueueConfig& config)
    -> std::expected<SplitQueue, QueueError> {
    if (config.size == 0 || config.size > max_queue_size || !std::has_single_bit(config.size)) {
        return std::unexpected(QueueError::bad_size);
    }
    if (config.desc % desc_table_align != 0 || config.driver % avail_ring_align != 0 ||
        config.device % used_ring_align != 0) {
        return std::unexpected(QueueError::misaligned_ring);
    }
    auto desc = memory.writable(config.desc, desc_table_bytes(config.size));
    auto avail = memory.writable(config.driver, avail_ring_bytes(config.size));
    auto used = memory.writable(config.device, used_ring_bytes(config.size));
    if (!desc || !avail || !used) {
        return std::unexpected(QueueError::ring_unmapped);
    }
    return SplitQueue{memory, config, *desc, *avail, *used};
}

SplitQueue::SplitQueue(const GuestMemory& memory, const QueueConfig& config,
                       std::span<std::byte> desc, std::span<std::byte> avail,
                       std::span<std::byte> used)
    : _memory{&memory},
      _config{config},
      _desc{desc},
      _avail{avail},
      _used{used},
      _capacity(config.size, 0),
      _in_flight(config.size, false) {}

auto SplitQueue::fail(QueueError e) -> std::unexpected<QueueError> {
    _broken = true;
    return std::unexpected(e);
}

auto SplitQueue::pop() -> std::expected<std::optional<Chain>, QueueError> {
    if (_broken) {
        return std::unexpected(QueueError::broken);
    }
    const std::uint16_t avail_idx = load16(_avail, ring_idx_offset);
    const auto pending = static_cast<std::uint16_t>(avail_idx - _last_avail);
    if (pending == 0) {
        return std::optional<Chain>{};
    }
    if (pending > _config.size) {
        return fail(QueueError::avail_index_jump);
    }
    // Ring entries are read only after the index that published them.
    std::atomic_thread_fence(std::memory_order_acquire);

    const std::size_t slot = _last_avail & (_config.size - 1);
    const std::uint16_t head = load16(_avail, ring_entries_offset + (slot * avail_entry_size));
    if (head >= _config.size) {
        return fail(QueueError::head_out_of_range);
    }
    if (_in_flight[head]) {
        return fail(QueueError::head_in_flight);
    }
    auto chain = walk(head);
    if (!chain) {
        return fail(chain.error());
    }
    ++_last_avail;
    _in_flight[head] = true;
    _capacity[head] = chain->writable_bytes;
    ++_in_flight_count;
    return std::optional<Chain>{std::move(*chain)};
}

auto SplitQueue::rewalk(std::uint16_t head) -> std::expected<Chain, QueueError> {
    if (_broken) {
        return std::unexpected(QueueError::broken);
    }
    if (head >= _config.size || !_in_flight[head]) {
        return std::unexpected(QueueError::unknown_head);
    }
    auto chain = walk(head);
    if (!chain) {
        return fail(chain.error());
    }
    // push() may fill what the chain holds now.
    _capacity[head] = chain->writable_bytes;
    return chain;
}

auto SplitQueue::add_buffer(Chain& chain, const Descriptor& d, bool& seen_writable)
    -> std::expected<void, QueueError> {
    if ((d.flags & desc_f_write) != 0) {
        auto buf = _memory->writable(d.addr, d.len);
        if (!buf) {
            return std::unexpected(QueueError::buffer_unmapped);
        }
        seen_writable = true;
        chain.writable.push_back(*buf);
        chain.writable_bytes += d.len;
    } else {
        if (seen_writable) {
            return std::unexpected(QueueError::readable_after_writable);
        }
        auto buf = _memory->readable(d.addr, d.len);
        if (!buf) {
            return std::unexpected(QueueError::buffer_unmapped);
        }
        chain.readable.push_back(*buf);
        chain.readable_bytes += d.len;
    }
    return {};
}

auto SplitQueue::walk(std::uint16_t head) -> std::expected<Chain, QueueError> {
    // Copies one 16-byte descriptor out of a table; the index is in range.
    auto read_desc = [](std::span<const std::byte> table, std::size_t index) -> Descriptor {
        wire::Reader r{table.subspan(index * descriptor_size, descriptor_size)};
        // Cannot fail: the subspan is exactly one descriptor.
        return Descriptor{.addr = r.le64().value_or(0),
                          .len = r.le32().value_or(0),
                          .flags = r.le16().value_or(0),
                          .next = r.le16().value_or(0)};
    };

    Chain chain;
    chain.head = head;
    bool seen_writable = false;
    std::size_t budget = _config.size;
    std::uint16_t index = head;

    for (;;) {
        if (budget-- == 0) {
            return std::unexpected(QueueError::chain_too_long);
        }
        const Descriptor d = read_desc(_desc, index);

        if ((d.flags & desc_f_indirect) != 0) {
            if (!_config.indirect_desc) {
                return std::unexpected(QueueError::indirect_not_negotiated);
            }
            if ((d.flags & desc_f_next) != 0) {
                return std::unexpected(QueueError::indirect_with_next);
            }
            if (d.len == 0 || d.len % descriptor_size != 0) {
                return std::unexpected(QueueError::bad_indirect_length);
            }
            auto table = _memory->readable(d.addr, d.len);
            if (!table) {
                return std::unexpected(QueueError::buffer_unmapped);
            }
            const std::size_t count = d.len / descriptor_size;
            // The indirect descriptor itself took one from the budget; its
            // entries take the rest.
            std::size_t i = 0;
            for (;;) {
                if (budget-- == 0) {
                    return std::unexpected(QueueError::chain_too_long);
                }
                const Descriptor e = read_desc(*table, i);
                if ((e.flags & desc_f_indirect) != 0) {
                    return std::unexpected(QueueError::nested_indirect);
                }
                if (auto ok = add_buffer(chain, e, seen_writable); !ok) {
                    return std::unexpected(ok.error());
                }
                if ((e.flags & desc_f_next) == 0) {
                    return chain;
                }
                if (e.next >= count) {
                    return std::unexpected(QueueError::next_out_of_range);
                }
                i = e.next;
            }
        }

        if (auto ok = add_buffer(chain, d, seen_writable); !ok) {
            return std::unexpected(ok.error());
        }
        if ((d.flags & desc_f_next) == 0) {
            return chain;
        }
        if (d.next >= _config.size) {
            return std::unexpected(QueueError::next_out_of_range);
        }
        index = d.next;
    }
}

auto SplitQueue::push(std::uint16_t head, std::uint32_t written)
    -> std::expected<void, QueueError> {
    if (_broken) {
        return std::unexpected(QueueError::broken);
    }
    // A device bug, not a guest one: report it but keep the queue usable.
    if (head >= _config.size || !_in_flight[head]) {
        return std::unexpected(QueueError::unknown_head);
    }
    if (written > _capacity[head]) {
        return std::unexpected(QueueError::used_length_too_large);
    }
    const std::size_t slot = _used_idx & (_config.size - 1);
    const std::size_t entry = ring_entries_offset + (slot * used_entry_size);
    store32(_used, entry, head);
    store32(_used, entry + used_entry_len_offset, written);
    // The entry must be visible before the index that publishes it.
    std::atomic_thread_fence(std::memory_order_release);
    ++_used_idx;
    store16(_used, ring_idx_offset, _used_idx);

    _in_flight[head] = false;
    _capacity[head] = 0;
    --_in_flight_count;
    return {};
}

auto SplitQueue::needs_interrupt() -> bool {
    if (_broken) {
        return false;
    }
    // Our used idx store must be visible before we read the driver's
    // suppression state (the other half of the driver's barrier).
    std::atomic_thread_fence(std::memory_order_seq_cst);
    const std::uint16_t old_idx = _signalled_used;
    _signalled_used = _used_idx;
    if (old_idx == _used_idx) {
        return false;
    }
    if (_config.event_idx) {
        const std::uint16_t used_event =
            load16(_avail, ring_entries_offset + (_config.size * avail_entry_size));
        return need_event(used_event, _used_idx, old_idx);
    }
    return (load16(_avail, ring_flags_offset) & avail_f_no_interrupt) == 0;
}

auto SplitQueue::set_notifications(bool enabled) -> void {
    if (_broken) {
        return;
    }
    if (_config.event_idx) {
        // Notify when the driver publishes past what we have consumed.
        if (enabled) {
            store16(_used, ring_entries_offset + (_config.size * used_entry_size), _last_avail);
        }
    } else {
        store16(_used, ring_flags_offset, enabled ? 0 : used_f_no_notify);
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

}  // namespace ak::oar::virtio
