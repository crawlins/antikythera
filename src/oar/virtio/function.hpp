// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A whole modern virtio PCI function, written once and bound to a transport
// (.kiro/specs/oar-net-data-plane/ Requirement 1.4,
// .kiro/steering/structure.md "One transport seam per device").
//
// PciFunction is the seam. A transport (vfio-user in harbor, pci-epf on
// hardware) owns config space, the BARs, DMA mappings and MSI-X, and talks
// to the function only through this class: it places capabilities(), routes
// BAR accesses to bar_read()/bar_write(), registers guest memory, forwards
// FLR to reset() and raises the vectors InterruptSink asks for. The device
// type (virtio-net, virtio-blk) implements Device and sees only its own
// configuration window, queue notifications and resets.
//
// Everything lives in one memory BAR:
//
//   0x0000  common configuration (pci.hpp CommonConfig)
//   0x1000  ISR status, 1 byte, read-to-clear
//   0x2000  device-specific configuration (Device::read_config)
//   0x3000  notify: queue N at N * notify_off_multiplier, 16-bit writes
//
// Queues come alive when the driver sets DRIVER_OK: each enabled queue's
// rings are resolved against GuestMemory once, then the device drives them
// through queue(). A guest error in a ring (QueueError) or a ring the
// driver enabled at an address it does not own puts the function in
// DEVICE_NEEDS_RESET (spec 2.1.2): all queues are dropped and a config
// interrupt tells the driver. Nothing a guest writes can make the function
// throw or touch memory outside GuestMemory.
//
// Not thread-safe: the transport serializes every call.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <vector>

#include "oar/virtio/guest_memory.hpp"
#include "oar/virtio/pci.hpp"
#include "oar/virtio/split_queue.hpp"

namespace ak::oar::virtio {

// BAR layout, shared by every device so one transport fits all of them.
namespace bar_layout {
inline constexpr std::uint8_t bar_index = 0;
inline constexpr std::uint32_t common_offset = 0x0000;
inline constexpr std::uint32_t isr_offset = 0x1000;
inline constexpr std::uint32_t isr_length = 1;
inline constexpr std::uint32_t device_offset = 0x2000;
inline constexpr std::uint32_t device_max_length = 0x1000;
inline constexpr std::uint32_t notify_offset = 0x3000;
inline constexpr std::uint32_t notify_off_multiplier = 4;
inline constexpr std::uint32_t notify_max_length = 0x1000;
inline constexpr std::uint32_t bar_size = 0x4000;
}  // namespace bar_layout

// ISR status bits (spec 4.1.4.5).
inline constexpr std::uint8_t isr_queue = 1;
inline constexpr std::uint8_t isr_config = 2;

// What the transport needs to present the function on the bus.
struct PciIdentity {
    std::uint16_t device_id{0};  // 0x1040 + virtio device type (spec 4.1.2.1)
    std::uint8_t class_code{0};
    std::uint8_t subclass{0};
    std::uint8_t prog_if{0};
};

inline constexpr std::uint16_t pci_vendor_virtio = 0x1AF4;
inline constexpr std::uint16_t pci_device_id_modern_base = 0x1040;
// Modern-only devices have a non-zero revision (spec 4.1.2.1).
inline constexpr std::uint8_t pci_revision_modern = 1;

// The device type's side of the seam.
class Device {
public:
    Device() = default;
    Device(const Device&) = delete;
    auto operator=(const Device&) -> Device& = delete;
    Device(Device&&) = delete;
    auto operator=(Device&&) -> Device& = delete;
    virtual ~Device() = default;

    // A driver access to the device-specific configuration window, already
    // checked to lie inside [0, device_config_size).
    [[nodiscard]] virtual auto read_config(std::uint32_t offset, std::size_t width) const
        -> std::expected<std::uint64_t, AccessError> = 0;
    [[nodiscard]] virtual auto write_config(std::uint32_t offset, std::size_t width,
                                            std::uint64_t value)
        -> std::expected<void, AccessError> = 0;

    // The driver kicked a live queue.
    virtual auto queue_notified(std::uint16_t index) -> void = 0;
    // Work deferred past a budget; returns true while more remains.
    [[nodiscard]] virtual auto poll() -> bool = 0;
    // Queues were dropped (driver reset, FLR or DEVICE_NEEDS_RESET); forget
    // everything tied to them.
    virtual auto queues_dropped() -> void = 0;
};

// MSI-X delivery, provided by the transport.
class InterruptSink {
public:
    InterruptSink() = default;
    InterruptSink(const InterruptSink&) = delete;
    auto operator=(const InterruptSink&) -> InterruptSink& = delete;
    InterruptSink(InterruptSink&&) = delete;
    auto operator=(InterruptSink&&) -> InterruptSink& = delete;
    virtual ~InterruptSink() = default;

    virtual auto raise(std::uint16_t vector) -> void = 0;
};

struct PciFunctionParams {
    PciIdentity identity;
    std::uint64_t device_features{0};  // must include VERSION_1
    std::uint16_t num_queues{0};
    std::uint16_t max_queue_size{0};
    std::uint32_t device_config_size{0};  // <= bar_layout::device_max_length
};

enum class FunctionError : std::uint8_t {
    bad_config,          // CommonConfig rejected the parameters
    device_config_size,  // device window larger than the BAR slot
    too_many_queues,     // notify window cannot hold every queue
};

[[nodiscard]] auto to_string(FunctionError e) noexcept -> const char*;

class PciFunction {
public:
    // `device`, `memory` and `interrupts` must outlive the function.
    [[nodiscard]] static auto create(Device& device, const GuestMemory& memory,
                                     InterruptSink& interrupts, const PciFunctionParams& params)
        -> std::expected<std::unique_ptr<PciFunction>, FunctionError>;

    PciFunction(const PciFunction&) = delete;
    auto operator=(const PciFunction&) -> PciFunction& = delete;
    PciFunction(PciFunction&&) = delete;
    auto operator=(PciFunction&&) -> PciFunction& = delete;
    ~PciFunction() = default;

    // --- Transport side --------------------------------------------------

    [[nodiscard]] auto identity() const noexcept -> const PciIdentity& { return _params.identity; }
    // Vendor capabilities for config space, in order: common, notify, ISR,
    // device. Encode each with encode_capability().
    [[nodiscard]] auto capabilities() const -> std::vector<PciCapability>;
    // One vector per queue plus one for configuration changes.
    [[nodiscard]] auto msix_vectors() const noexcept -> std::uint16_t {
        return static_cast<std::uint16_t>(_params.num_queues + 1U);
    }

    // A driver access of `width` bytes at `offset` in the BAR. Reading ISR
    // clears it, so reads are not const. Errors change nothing; the
    // transport completes the access anyway (reads as zero).
    [[nodiscard]] auto bar_read(std::uint32_t offset, std::size_t width)
        -> std::expected<std::uint64_t, AccessError>;
    [[nodiscard]] auto bar_write(std::uint32_t offset, std::size_t width, std::uint64_t value)
        -> std::expected<void, AccessError>;

    // FLR or power-on: every register back to its reset value, queues and
    // in-flight buffers gone (Requirement 1.3).
    auto reset() -> void;
    // The transport is about to remove guest memory it cannot describe:
    // live queues are dropped and a live driver sees DEVICE_NEEDS_RESET.
    auto memory_changing() -> void;
    // The transport is about to remove [gpa, gpa + len). Only a live ring
    // (descriptor table, available or used ring) inside that range forces
    // DEVICE_NEEDS_RESET. Buffers are translated afresh on every pop and no
    // device keeps their spans between calls, so nothing else can dangle:
    // a device that completes a chain later keeps its guest addresses and
    // translates them again (Chain::writable_gpa).
    // Hosts unmap ranges that never held rings all the time: the VMM drops
    // and re-adds the window of every BAR whose decoding the guest
    // toggles, and those windows are DMA regions too. Failing the device
    // for each would wedge a live driver (Linux does not recover from
    // DEVICE_NEEDS_RESET), which is how an L1 host hung while probing a
    // second function.
    auto memory_changing(Gpa gpa, std::uint64_t len) -> void;
    // Deferred device work (Device::poll); true while more remains.
    [[nodiscard]] auto poll() -> bool;

    // --- Device side -----------------------------------------------------

    // A live queue, or nullptr before DRIVER_OK, after a reset, or for a
    // queue the driver did not enable.
    [[nodiscard]] auto queue(std::uint16_t index) -> SplitQueue*;
    // Raises the queue's interrupt if the driver wants one for what was
    // pushed since the last call.
    auto signal(std::uint16_t index) -> void;
    // The guest broke a ring: DEVICE_NEEDS_RESET, queues dropped, config
    // interrupt.
    auto fail() -> void;
    // Device-specific configuration changed: bump the generation and raise
    // the config interrupt (spec 4.1.4.3.1).
    auto config_changed() -> void;

    [[nodiscard]] auto live() const noexcept -> bool { return _live; }
    [[nodiscard]] auto negotiated(unsigned bit) const noexcept -> bool {
        return (_common.negotiated_features() & feature_bit(bit)) != 0;
    }
    [[nodiscard]] auto status() const noexcept -> std::uint8_t { return _common.status(); }

private:
    PciFunction(Device& device, const GuestMemory& memory, InterruptSink& interrupts,
                const PciFunctionParams& params, CommonConfig common);

    auto after_common_write() -> void;
    auto activate() -> void;
    auto drop_queues() -> void;
    auto raise_config() -> void;

    Device* _device;
    const GuestMemory* _memory;
    InterruptSink* _interrupts;
    PciFunctionParams _params;
    CommonConfig _common;
    std::vector<std::optional<SplitQueue>> _queues;
    std::uint8_t _isr{0};
    bool _live{false};
};

}  // namespace ak::oar::virtio
