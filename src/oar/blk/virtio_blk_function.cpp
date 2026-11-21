// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/virtio_blk_function.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <utility>

#include <openssl/crypto.h>

#include "common/wire.hpp"

namespace ak::oar::blk {

namespace {

namespace wire = ak::wire;

constexpr std::uint8_t pci_class_storage = 0x01;
constexpr std::uint8_t pci_subclass_scsi = 0x00;  // what virtio-blk reports (QEMU, Linux)
constexpr std::uint8_t pci_prog_if_none = 0x00;
constexpr std::size_t width8 = 1;
constexpr std::size_t width16 = 2;
constexpr std::size_t width32 = 4;
constexpr std::size_t width64 = 8;
constexpr unsigned bits_per_byte = 8;

auto device_features(const BlkParams& params) -> std::uint64_t {
    using virtio::feature_bit;
    std::uint64_t f =
        feature_bit(virtio::feature_version_1) | feature_bit(virtio::feature_access_platform) |
        feature_bit(virtio::feature_indirect_desc) | feature_bit(virtio::feature_event_idx) |
        feature_bit(feature_blk_size_max) | feature_bit(feature_blk_seg_max) |
        feature_bit(feature_blk_blk_size) | feature_bit(feature_blk_flush);
    if (params.geometry.read_only) {
        f |= feature_bit(feature_blk_ro);
    }
    if (params.num_queues > 1) {
        f |= feature_bit(feature_blk_mq);
    }
    return f;
}

// The bytes of `segments`, in order, copied into `out` (same total size).
auto gather(std::span<const std::span<const std::byte>> segments, std::span<std::byte> out)
    -> void {
    std::size_t at = 0;
    for (auto seg : segments) {
        std::memcpy(out.data() + at, seg.data(), seg.size());
        at += seg.size();
    }
}

// `in` copied out over `segments`, in order (same total size).
auto scatter(std::span<const std::byte> in, std::span<const std::span<std::byte>> segments)
    -> void {
    std::size_t at = 0;
    for (auto seg : segments) {
        std::memcpy(seg.data(), in.data() + at, seg.size());
        at += seg.size();
    }
}

}  // namespace

auto to_string(BackendError e) noexcept -> const char* {
    switch (e) {
        case BackendError::io:
            return "io";
        case BackendError::out_of_range:
            return "out_of_range";
    }
    return "unknown";
}

auto to_string(BlkConfigError e) noexcept -> const char* {
    switch (e) {
        case BlkConfigError::bad_geometry:
            return "bad_geometry";
        case BlkConfigError::bad_transfer:
            return "bad_transfer";
        case BlkConfigError::bad_queues:
            return "bad_queues";
        case BlkConfigError::bad_budget:
            return "bad_budget";
        case BlkConfigError::serial_too_long:
            return "serial_too_long";
        case BlkConfigError::backend_missing:
            return "backend_missing";
        case BlkConfigError::backend_too_small:
            return "backend_too_small";
        case BlkConfigError::key_slot:
            return "key_slot";
    }
    return "unknown";
}

auto to_string(KeyError e) noexcept -> const char* {
    switch (e) {
        case KeyError::occupied:
            return "occupied";
        case KeyError::rejected:
            return "rejected";
        case KeyError::slot:
            return "slot";
    }
    return "unknown";
}

auto VirtioBlkFunction::create(const BlkParams& params, const virtio::GuestMemory& memory,
                               virtio::InterruptSink& interrupts,
                               std::unique_ptr<BlockBackend> backend)
    -> std::expected<std::unique_ptr<VirtioBlkFunction>, BlkConfigError> {
    auto parser = RequestParser::create(params.geometry);
    if (!parser) {
        return std::unexpected(BlkConfigError::bad_geometry);
    }
    const VolumeGeometry& g = params.geometry;
    if (g.max_transfer_bytes > max_bounce_bytes ||
        g.max_transfer_bytes / g.seg_max < min_segment_bytes) {
        return std::unexpected(BlkConfigError::bad_transfer);
    }
    if (params.budget == 0) {
        return std::unexpected(BlkConfigError::bad_budget);
    }
    if (params.serial.size() > id_bytes) {
        return std::unexpected(BlkConfigError::serial_too_long);
    }
    if (!backend) {
        return std::unexpected(BlkConfigError::backend_missing);
    }
    if (g.capacity_sectors > std::numeric_limits<std::uint64_t>::max() / sector_size ||
        backend->size_bytes() < g.capacity_sectors * sector_size) {
        return std::unexpected(BlkConfigError::backend_too_small);
    }
    auto key = KeySlot::create();
    if (!key) {
        return std::unexpected(BlkConfigError::key_slot);
    }
    // The constructor is private, so make_unique cannot reach it.
    std::unique_ptr<VirtioBlkFunction> fn{
        new VirtioBlkFunction(params, *parser, std::move(*key), std::move(backend))};
    auto pci = virtio::PciFunction::create(
        *fn, memory, interrupts,
        {.identity = {.device_id = static_cast<std::uint16_t>(virtio::pci_device_id_modern_base +
                                                              virtio_blk_device_type),
                      .class_code = pci_class_storage,
                      .subclass = pci_subclass_scsi,
                      .prog_if = pci_prog_if_none},
         .device_features = device_features(params),
         .num_queues = params.num_queues,
         .max_queue_size = params.queue_size,
         .device_config_size = blk_cfg::size});
    if (!pci) {
        return std::unexpected(BlkConfigError::bad_queues);
    }
    fn->_pci = std::move(*pci);
    return fn;
}

VirtioBlkFunction::VirtioBlkFunction(const BlkParams& params, RequestParser parser, KeySlot key,
                                     std::unique_ptr<BlockBackend> backend)
    : _parser{parser},
      _key{std::move(key)},
      _backend{std::move(backend)},
      _budget{params.budget},
      _queues(params.num_queues) {
    const VolumeGeometry& g = params.geometry;
    for (auto& q : _queues) {
        q.bounce.resize(g.max_transfer_bytes);
    }

    // virtio_blk_config, little-endian. Geometry and topology stay zero:
    // neither feature is offered.
    std::vector<std::byte> cfg;
    wire::Writer w{cfg};
    w.le64(g.capacity_sectors);
    w.le32(g.max_transfer_bytes / g.seg_max);  // size_max
    w.le32(g.seg_max);
    w.le32(0);  // geometry
    w.le32(g.logical_block_size);
    w.le64(0);  // topology
    w.u8(0);    // writeback
    w.u8(0);    // unused0
    w.le16(params.num_queues);
    std::ranges::copy(cfg, _device_config.begin());

    std::ranges::copy(std::as_bytes(std::span{params.serial}), _serial.begin());
}

VirtioBlkFunction::~VirtioBlkFunction() {
    wipe_bounce();
}

auto VirtioBlkFunction::read_config(std::uint32_t offset, std::size_t width) const
    -> std::expected<std::uint64_t, virtio::AccessError> {
    if (width != width8 && width != width16 && width != width32 && width != width64) {
        return std::unexpected(virtio::AccessError::bad_width);
    }
    if (offset % width != 0) {
        return std::unexpected(virtio::AccessError::bad_width);
    }
    if (offset >= blk_cfg::size || width > blk_cfg::size - offset) {
        return std::unexpected(virtio::AccessError::bad_offset);
    }
    std::uint64_t v = 0;
    for (std::size_t i = width; i-- > 0;) {
        v = (v << bits_per_byte) | std::to_integer<std::uint64_t>(_device_config[offset + i]);
    }
    return v;
}

auto VirtioBlkFunction::write_config(std::uint32_t offset, std::size_t width,
                                     std::uint64_t /*value*/)
    -> std::expected<void, virtio::AccessError> {
    // writeback is the only writable field, and only with CONFIG_WCE.
    return read_config(offset, width)
        .and_then([](std::uint64_t) -> std::expected<void, virtio::AccessError> {
            return std::unexpected(virtio::AccessError::read_only);
        });
}

auto VirtioBlkFunction::queue_notified(std::uint16_t index) -> void {
    if (index < _queues.size()) {
        _queues[index].pending = process(index);
    }
}

auto VirtioBlkFunction::poll() -> bool {
    bool more = false;
    for (std::size_t i = 0; i < _queues.size(); ++i) {
        if (!_queues[i].parked.empty()) {
            resume(static_cast<std::uint16_t>(i));
        }
        if (_queues[i].pending) {
            // num_queues is a u16, so every index fits.
            _queues[i].pending = process(static_cast<std::uint16_t>(i));
            more = more || _queues[i].pending;
        }
    }
    return more;
}

auto VirtioBlkFunction::queues_dropped() -> void {
    for (auto& q : _queues) {
        q.pending = false;
        q.parked.clear();  // their heads went with the rings
    }
}

auto VirtioBlkFunction::wipe_bounce() noexcept -> void {
    for (auto& q : _queues) {
        OPENSSL_cleanse(q.bounce.data(), q.bounce.size());
    }
}

auto VirtioBlkFunction::queue_error() -> void {
    ++_counters.queue_errors;
    _pci->fail();
}

auto VirtioBlkFunction::function_reset() -> void {
    _pci->reset();
    // The VMM's open resets the function before helm sends the key, so an
    // FLR does not end the wait for it.
    const bool awaiting = _awaiting_key;
    drop_key();
    _awaiting_key = awaiting;
    wipe_bounce();
    ++_counters.function_resets;
}

auto VirtioBlkFunction::deliver_key(XtsKey key) -> std::expected<void, KeyError> {
    if (_key.holds_key()) {
        return std::unexpected(KeyError::occupied);
    }
    if (!_key.load(key)) {
        return std::unexpected(KeyError::slot);
    }
    auto held = _key.key();
    if (!held) {
        drop_key();
        return std::unexpected(KeyError::slot);
    }
    for (auto& q : _queues) {
        auto cipher = XtsCipher::create(*held, _parser.geometry().logical_block_size);
        if (!cipher) {
            drop_key();
            return std::unexpected(cipher.error() == XtsError::weak_key ? KeyError::rejected
                                                                        : KeyError::slot);
        }
        q.cipher.emplace(std::move(*cipher));
    }
    if (_awaiting_key) {
        // Serve what queued up while waiting: the transport's next poll()
        // picks these up.
        _awaiting_key = false;
        for (auto& q : _queues) {
            q.pending = true;
        }
    }
    return {};
}

auto VirtioBlkFunction::await_key() noexcept -> void {
    if (!_key.holds_key()) {
        _awaiting_key = true;
    }
}

auto VirtioBlkFunction::drop_key() noexcept -> void {
    for (auto& q : _queues) {
        q.cipher.reset();  // EVP_CIPHER_CTX_free cleanses the key schedule
    }
    _key.drop();
    _awaiting_key = false;
}

auto VirtioBlkFunction::process(std::uint16_t index) -> bool {
    virtio::SplitQueue* ring = _pci->queue(index);
    if (ring == nullptr) {
        return false;
    }
    if (_awaiting_key) {
        // Left in the ring; deliver_key() marks the queue pending.
        return false;
    }
    Queue& q = _queues[index];
    ring->set_notifications(false);
    for (std::size_t done = 0;; ++done) {
        if (done == _budget) {
            // Notifications stay off; the transport calls poll() for the rest.
            _pci->signal(index);
            return true;
        }
        auto next = ring->pop();
        if (next && !next->has_value()) {
            // Re-enable, then look again: a buffer posted before the driver
            // saw the change would otherwise never be noticed.
            ring->set_notifications(true);
            next = ring->pop();
            if (next && !next->has_value()) {
                break;
            }
            ring->set_notifications(false);
        }
        if (!next) {
            queue_error();
            return false;
        }
        const virtio::Chain& chain = **next;
        const auto served = serve(q, chain, true);
        if (!served || (!served->parked && !ring->push(chain.head, served->written))) {
            queue_error();
            return false;
        }
    }
    _pci->signal(index);
    return false;
}

auto VirtioBlkFunction::resume(std::uint16_t index) -> void {
    virtio::SplitQueue* ring = _pci->queue(index);
    Queue& q = _queues[index];
    if (ring == nullptr) {
        q.parked.clear();
        return;
    }
    bool pushed = false;
    for (std::size_t i = 0; i < q.parked.size();) {
        const Parked p = q.parked[i];
        if (!_backend->read_ready(p.offset, p.len)) {
            ++i;
            continue;
        }
        q.parked.erase(q.parked.begin() + static_cast<std::ptrdiff_t>(i));
        ++_counters.resumed;
        auto chain = ring->rewalk(p.head);
        if (!chain) {
            queue_error();
            return;
        }
        // Not parked again: the request may have changed under us, and a
        // read the backend now calls ready is served even if it waits.
        const auto served = serve(q, *chain, false);
        if (!served || !ring->push(chain->head, served->written)) {
            queue_error();
            return;
        }
        pushed = true;
    }
    if (pushed) {
        _pci->signal(index);
    }
}

auto VirtioBlkFunction::serve(Queue& q, const virtio::Chain& chain, bool may_park)
    -> std::optional<Served> {
    auto parsed = _parser.parse(chain.readable, chain.writable);
    std::uint32_t data_written = 0;
    Status st = Status::ok;
    std::span<std::byte> status_byte;
    if (!parsed) {
        const Rejection& r = parsed.error();
        if (r.error == ParseError::no_status_byte) {
            return std::nullopt;
        }
        st = status_for(r.error);
        status_byte = r.status;
    } else {
        const Request& req = *parsed;
        status_byte = req.status;
        if (may_park && req.type == RequestType::in && q.cipher &&
            !_backend->read_ready(req.sector * sector_size, req.data_bytes)) {
            q.parked.push_back(
                {.head = chain.head, .offset = req.sector * sector_size, .len = req.data_bytes});
            ++_counters.parked;
            return Served{.parked = true, .written = 0};
        }
        switch (req.type) {
            case RequestType::in:
            case RequestType::out:
                st = do_io(q, req);
                if (st == Status::ok && req.type == RequestType::in) {
                    // data_bytes <= max_transfer_bytes <= max_bounce_bytes
                    data_written = static_cast<std::uint32_t>(req.data_bytes);
                }
                break;
            case RequestType::flush:
                st = _backend->flush() ? Status::ok : Status::ioerr;
                break;
            case RequestType::get_id:
                data_written = do_get_id(req);
                break;
            default:
                st = Status::unsupp;  // the parser admits no other type
                break;
        }
    }
    complete(status_byte, st);
    switch (st) {
        case Status::ok:
            ++_counters.completed;
            break;
        case Status::unsupp:
            ++_counters.failed_unsupp;
            break;
        case Status::ioerr:
            ++_counters.failed_ioerr;
            break;
    }
    // Bytes written into the chain: the data (IN, GET_ID) and the status.
    return Served{.parked = false,
                  .written = data_written + static_cast<std::uint32_t>(status_size)};
}

auto VirtioBlkFunction::do_io(Queue& q, const Request& req) -> Status {
    if (!q.cipher) {
        ++_counters.no_key;
        return Status::ioerr;  // no key: the volume cannot be read or written
    }
    const std::uint64_t offset = req.sector * sector_size;
    const std::uint64_t unit = req.sector / (_parser.geometry().logical_block_size / sector_size);
    const std::span<std::byte> buf = std::span{q.bounce}.first(req.data_bytes);

    if (req.type == RequestType::out) {
        // Copy once, so the guest cannot change the data between encrypting
        // and writing; the buffer holds ciphertext from here on.
        gather(req.out_data, buf);
        if (!q.cipher->encrypt(unit, buf, buf)) {
            OPENSSL_cleanse(buf.data(), buf.size());
            return Status::ioerr;
        }
        return _backend->write(offset, buf) ? Status::ok : Status::ioerr;
    }

    Status st = Status::ioerr;
    if (_backend->read(offset, buf) && q.cipher->decrypt(unit, buf, buf)) {
        scatter(buf, req.in_data);
        st = Status::ok;
    }
    OPENSSL_cleanse(buf.data(), buf.size());  // no plaintext left behind
    return st;
}

auto VirtioBlkFunction::do_get_id(const Request& req) -> std::uint32_t {
    std::size_t at = 0;
    for (auto seg : req.in_data) {
        const std::size_t n = std::min(seg.size(), _serial.size() - at);
        std::memcpy(seg.data(), _serial.data() + at, n);
        at += n;
        if (at == _serial.size()) {
            break;
        }
    }
    return static_cast<std::uint32_t>(at);
}

}  // namespace ak::oar::blk
