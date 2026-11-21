// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// One virtio-blk PCI function: the device that presents one volume
// attachment to one VM as a plaintext disk (.kiro/specs/oar-blk-data-plane/
// Requirement 1, design "VirtioBlkFunction").
//
// The function is a virtio::Device on the shared transport seam
// (oar/virtio/function.hpp, .kiro/steering/structure.md "One transport seam
// per device"): it owns a PciFunction, which handles the common
// configuration, ISR, notifications and queue setup, and the transport
// (vfio-user in harbor, pci-epf on hardware) drives that. The device
// itself sees only its configuration window (virtio_blk_config, read-only),
// queue kicks and resets.
//
// Offered features: VERSION_1, ACCESS_PLATFORM (descriptors carry IOVAs
// behind the IOMMU), INDIRECT_DESC, EVENT_IDX, SIZE_MAX, SEG_MAX, BLK_SIZE,
// FLUSH, plus RO for a read-only attachment and MQ with more than one
// queue. size_max is max_transfer_bytes / seg_max, so no request the driver
// can build exceeds the transfer cap the parser enforces.
//
// Requests are served in queue_notified(), up to a budget per call; the
// rest wait for poll(). A read the backend cannot serve without waiting is
// parked (below). Each one goes through RequestParser
// (bounds, shape, range) before any I/O, then:
//
//   OUT    guest plaintext is copied once into the queue's bounce buffer,
//          encrypted there in place with AES-256-XTS, and the ciphertext is
//          written to the backend: the backend never sees plaintext;
//   IN     ciphertext is read into the bounce buffer, decrypted in place,
//          copied out to the guest, and the bounce buffer is wiped;
//   FLUSH  forwarded to the backend;
//   GET_ID the attachment's serial, zero-padded to 20 bytes.
//
// Parking (oar-blk Requirement 8.10, design "Asynchronous misses"). Before
// an IN with a key held, the function asks the backend whether the read is
// ready (BlockBackend::read_ready). If not, it parks the request: it keeps
// only the head and the range, leaves the chain in flight, and goes on with
// the rest of the ring, so a cold image chunk delays only the requests that
// need it. poll() asks again for every parked request and serves the ready
// ones, translating the chain afresh (SplitQueue::rewalk) and serving it
// as if it had just been popped, without parking it a second time.
// virtio-blk completes requests in any order, and a request the guest
// issued concurrently with another has no order relative to it. Dropping
// the queues forgets parked requests with their rings; dropping the key
// leaves them parked, and they fail with IOERR when served.
//
// The XTS data unit is the logical block (512 B or 4 KiB) and its tweak is
// the logical block number, so sector s of a 4 KiB volume is in unit s / 8
// (Requirement 2.1, design "XtsCipher").
//
// The volume key lives in a KeySlot (locked, undumpable page) and in one
// XtsCipher per queue, built from it when helm delivers the key. Without a
// key, IN and OUT complete with IOERR; FLUSH and GET_ID still work, since
// neither touches volume data. drop_key() and function_reset() wipe the
// slot and free the ciphers (OpenSSL cleanses their key schedules), so the
// key is gone on detach, FLR and destruction (Requirements 1.2, 2.3).
//
// A driver-initiated reset (device_status = 0) is not an FLR: the guest
// driver resets the device every time it probes it, so that reset drops the
// queues but keeps the key. Only the transport's FLR (function_reset), helm's
// drop_key and destruction remove the key.
//
// Attach order. helm delivers the key only after the VMM has opened the
// function (opening a VFIO device resets it, which would wipe the key), so
// a guest can start probing the disk before the key is there. await_key()
// covers that window: until deliver_key() or drop_key(), requests are left
// in the rings untouched, not failed, so the guest's first reads wait
// rather than see I/O errors. An FLR in the window keeps the wait; the
// requests left waiting are served once the key arrives.
//
// A ring error, or a request with no writable status byte (which cannot be
// completed), puts the function in DEVICE_NEEDS_RESET (PciFunction::fail).
//
// Not thread-safe: the transport serializes every call.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "oar/blk/key_slot.hpp"
#include "oar/blk/request_parser.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "oar/virtio/function.hpp"

namespace ak::oar::blk {

// Virtio device type 2 (virtio 1.2 5.2.1).
inline constexpr std::uint16_t virtio_blk_device_type = 2;

// virtio-blk feature bits (virtio 1.2 5.2.3) that the function may offer.
inline constexpr unsigned feature_blk_size_max = 1;
inline constexpr unsigned feature_blk_seg_max = 2;
inline constexpr unsigned feature_blk_ro = 5;
inline constexpr unsigned feature_blk_blk_size = 6;
inline constexpr unsigned feature_blk_flush = 9;
inline constexpr unsigned feature_blk_mq = 12;

// struct virtio_blk_config (virtio 1.2 5.2.4), up to and including
// num_queues; the discard and write-zeroes fields that follow belong to
// features this function does not offer.
namespace blk_cfg {
inline constexpr std::uint32_t capacity = 0;     // le64, 512-byte sectors
inline constexpr std::uint32_t size_max = 8;     // le32
inline constexpr std::uint32_t seg_max = 12;     // le32
inline constexpr std::uint32_t geometry = 16;    // cylinders le16, heads u8, sectors u8
inline constexpr std::uint32_t blk_size = 20;    // le32
inline constexpr std::uint32_t topology = 24;    // 8 bytes
inline constexpr std::uint32_t writeback = 32;   // u8
inline constexpr std::uint32_t num_queues = 34;  // le16
inline constexpr std::uint32_t size = 36;
}  // namespace blk_cfg

// Linux needs each data segment to hold at least one page (it refuses a
// max_segment_size below PAGE_SIZE), so size_max may not go lower.
inline constexpr std::uint32_t min_segment_bytes = 4096;
// Largest max_transfer_bytes: each queue holds a bounce buffer this big.
inline constexpr std::uint32_t max_bounce_bytes = 16U << 20U;

enum class BackendError : std::uint8_t {
    io,            // the backing store failed the operation
    out_of_range,  // offset + length past the end of the backing store
};

[[nodiscard]] auto to_string(BackendError e) noexcept -> const char*;

// Where one volume's ciphertext lives: a sparse file in harbor (oar-blk
// task 5), an NVMe namespace on the board. Offsets are volume byte offsets
// (512 * sector); any metadata header is the backend's own business.
class BlockBackend {
public:
    BlockBackend() = default;
    BlockBackend(const BlockBackend&) = delete;
    auto operator=(const BlockBackend&) -> BlockBackend& = delete;
    BlockBackend(BlockBackend&&) = delete;
    auto operator=(BlockBackend&&) -> BlockBackend& = delete;
    virtual ~BlockBackend() = default;

    // Bytes of volume data the backend holds.
    [[nodiscard]] virtual auto size_bytes() const noexcept -> std::uint64_t = 0;
    [[nodiscard]] virtual auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, BackendError> = 0;
    // Whether read() of this range can finish without waiting on anything
    // slower than local storage. A backend that answers false has started
    // what the range waits for and will signal the role's Waker when it
    // arrives; the function parks the request and asks again then. The
    // answer is a hint: read() must still work (perhaps slowly) either way.
    [[nodiscard]] virtual auto read_ready(std::uint64_t /*offset*/, std::size_t /*len*/) -> bool {
        return true;
    }
    [[nodiscard]] virtual auto write(std::uint64_t offset, std::span<const std::byte> in)
        -> std::expected<void, BackendError> = 0;
    // Makes every completed write durable.
    [[nodiscard]] virtual auto flush() -> std::expected<void, BackendError> = 0;
};

struct BlkParams {
    VolumeGeometry geometry;
    std::uint16_t num_queues{1};
    std::uint16_t queue_size{256};
    // Requests served per queue_notified() before deferring to poll().
    std::size_t budget{256};
    // VIRTIO_BLK_T_GET_ID answer; at most 20 bytes, zero-padded on the wire.
    std::string_view serial;
};

enum class BlkConfigError : std::uint8_t {
    bad_geometry,       // RequestParser refused the geometry
    bad_transfer,       // max_transfer_bytes / seg_max below min_segment_bytes,
                        // or max_transfer_bytes above max_bounce_bytes
    bad_queues,         // num_queues or queue_size refused by the virtio core
    bad_budget,         // zero
    serial_too_long,    // more than 20 bytes
    backend_missing,    // no backend
    backend_too_small,  // backend holds less than capacity_sectors * 512 bytes
    key_slot,           // the KeySlot could not be created (mmap/mlock/madvise)
};

enum class KeyError : std::uint8_t {
    occupied,  // a key is already held: helm must drop_key first
    rejected,  // XtsCipher refused the key (equal halves)
    slot,      // the KeySlot failed
};

[[nodiscard]] auto to_string(BlkConfigError e) noexcept -> const char*;
[[nodiscard]] auto to_string(KeyError e) noexcept -> const char*;

struct BlkCounters {
    std::uint64_t completed{0};        // requests completed with OK
    std::uint64_t failed_ioerr{0};     // completed with IOERR
    std::uint64_t failed_unsupp{0};    // completed with UNSUPP
    std::uint64_t no_key{0};           // IN/OUT refused because no key is held
    std::uint64_t queue_errors{0};     // DEVICE_NEEDS_RESET raised by this device
    std::uint64_t function_resets{0};  // FLRs
    std::uint64_t parked{0};           // reads parked until the backend was ready
    std::uint64_t resumed{0};          // parked reads served
};

class VirtioBlkFunction final : public virtio::Device {
public:
    // `memory` and `interrupts` belong to the transport and must outlive
    // the function.
    [[nodiscard]] static auto create(const BlkParams& params, const virtio::GuestMemory& memory,
                                     virtio::InterruptSink& interrupts,
                                     std::unique_ptr<BlockBackend> backend)
        -> std::expected<std::unique_ptr<VirtioBlkFunction>, BlkConfigError>;

    VirtioBlkFunction(const VirtioBlkFunction&) = delete;
    auto operator=(const VirtioBlkFunction&) -> VirtioBlkFunction& = delete;
    VirtioBlkFunction(VirtioBlkFunction&&) = delete;
    auto operator=(VirtioBlkFunction&&) -> VirtioBlkFunction& = delete;
    // Wipes the bounce buffers; the KeySlot wipes the key.
    ~VirtioBlkFunction() override;

    // The transport seam.
    [[nodiscard]] auto pci() noexcept -> virtio::PciFunction& { return *_pci; }

    // FLR: the PciFunction is reset and the key and any plaintext are wiped,
    // so the function holds neither afterwards (Requirement 1.2). The
    // transport calls this instead of pci().reset().
    auto function_reset() -> void;

    // helm (over this role's sideband, Requirement 2.5): loads the volume
    // key and builds one cipher per queue. The caller wipes its own copy.
    [[nodiscard]] auto deliver_key(XtsKey key) -> std::expected<void, KeyError>;
    // Wipes the key and frees the ciphers, and ends an await_key() wait.
    // Safe without a key.
    auto drop_key() noexcept -> void;
    // Holds every request until deliver_key() or drop_key() (the attach
    // window above). No effect while a key is held.
    auto await_key() noexcept -> void;
    [[nodiscard]] auto awaiting_key() const noexcept -> bool { return _awaiting_key; }
    [[nodiscard]] auto holds_key() const noexcept -> bool { return _key.holds_key(); }

    [[nodiscard]] auto geometry() const noexcept -> const VolumeGeometry& {
        return _parser.geometry();
    }
    [[nodiscard]] auto counters() const noexcept -> const BlkCounters& { return _counters; }

    // virtio::Device
    [[nodiscard]] auto read_config(std::uint32_t offset, std::size_t width) const
        -> std::expected<std::uint64_t, virtio::AccessError> override;
    [[nodiscard]] auto write_config(std::uint32_t offset, std::size_t width, std::uint64_t value)
        -> std::expected<void, virtio::AccessError> override;
    auto queue_notified(std::uint16_t index) -> void override;
    [[nodiscard]] auto poll() -> bool override;
    auto queues_dropped() -> void override;

private:
    // A read waiting for its backend: the chain stays in flight.
    struct Parked {
        std::uint16_t head{0};
        std::uint64_t offset{0};
        std::size_t len{0};
    };

    struct Queue {
        std::optional<XtsCipher> cipher;
        std::vector<std::byte> bounce;  // max_transfer_bytes
        bool pending{false};            // budget ran out; poll() continues
        std::vector<Parked> parked;
    };

    // What serving a chain came to.
    struct Served {
        bool parked{false};
        std::uint32_t written{0};  // bytes written into the chain, when not parked
    };

    VirtioBlkFunction(const BlkParams& params, RequestParser parser, KeySlot key,
                      std::unique_ptr<BlockBackend> backend);

    // Serves up to the budget; true if requests remain.
    auto process(std::uint16_t index) -> bool;
    // Serves the parked requests whose backend is now ready.
    auto resume(std::uint16_t index) -> void;
    // Serves one chain, or parks it (only with may_park); nullopt if it
    // cannot be completed (no status byte).
    auto serve(Queue& q, const virtio::Chain& chain, bool may_park) -> std::optional<Served>;
    auto do_io(Queue& q, const Request& req) -> Status;
    auto do_get_id(const Request& req) -> std::uint32_t;
    auto queue_error() -> void;
    auto wipe_bounce() noexcept -> void;

    std::unique_ptr<virtio::PciFunction> _pci;
    RequestParser _parser;
    KeySlot _key;
    std::unique_ptr<BlockBackend> _backend;
    std::size_t _budget;
    std::vector<Queue> _queues;
    std::array<std::byte, blk_cfg::size> _device_config{};
    std::array<std::byte, id_bytes> _serial{};
    bool _awaiting_key{false};
    BlkCounters _counters;
};

}  // namespace ak::oar::blk
