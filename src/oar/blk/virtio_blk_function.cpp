// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/virtio_blk_function.hpp"

#include <algorithm>
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
        case BlkConfigError::bad_in_flight:
            return "bad_in_flight";
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
    if (params.max_in_flight == 0 || params.max_in_flight > params.queue_size) {
        return std::unexpected(BlkConfigError::bad_in_flight);
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
        new VirtioBlkFunction(params, *parser, std::move(*key), memory, std::move(backend))};
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
                                     const virtio::GuestMemory& memory,
                                     std::unique_ptr<BlockBackend> backend)
    : _parser{parser},
      _key{std::move(key)},
      _memory{&memory},
      _backend{std::move(backend)},
      _budget{params.budget},
      _queues(params.num_queues) {
    const VolumeGeometry& g = params.geometry;
    for (auto& q : _queues) {
        q.slots.resize(params.max_in_flight);
        for (auto& slot : q.slots) {
            slot.bounce.resize(g.max_transfer_bytes);
        }
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
    // The backend first: destroying it drops its pending completions and
    // ends its use of the bounce buffers, which can then all be wiped.
    _backend.reset();
    for (auto& q : _queues) {
        for (auto& slot : q.slots) {
            slot.busy = false;
        }
    }
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
    // Completions first: they free slots that queued requests are waiting for.
    const bool backend_busy = _backend->poll();
    bool more = false;
    for (std::size_t i = 0; i < _queues.size(); ++i) {
        if (_queues[i].pending) {
            // num_queues is a u16, so every index fits.
            _queues[i].pending = process(static_cast<std::uint16_t>(i));
            more = more || _queues[i].pending;
        }
    }
    signal_queues();
    // In flight without a wake descriptor: only polling notices completions.
    return more || ((backend_busy || _in_flight != 0) && _backend->wake_fd() < 0);
}

auto VirtioBlkFunction::queues_dropped() -> void {
    for (auto& q : _queues) {
        q.pending = false;
        q.signal = false;
    }
    abandon_in_flight();
}

auto VirtioBlkFunction::abandon_in_flight() noexcept -> void {
    for (auto& q : _queues) {
        for (auto& slot : q.slots) {
            if (slot.busy && !slot.abandoned) {
                slot.abandoned = true;
                ++_counters.abandoned;
            }
        }
    }
}

auto VirtioBlkFunction::wipe_bounce() noexcept -> void {
    for (auto& q : _queues) {
        for (auto& slot : q.slots) {
            if (!slot.busy) {
                OPENSSL_cleanse(slot.bounce.data(), slot.bounce.size());
            }
        }
    }
}

auto VirtioBlkFunction::signal_queues() -> void {
    for (std::size_t i = 0; i < _queues.size(); ++i) {
        if (_queues[i].signal) {
            _queues[i].signal = false;
            _pci->signal(static_cast<std::uint16_t>(i));
        }
    }
}

auto VirtioBlkFunction::queue_error() -> void {
    ++_counters.queue_errors;
    _pci->fail();
}

auto VirtioBlkFunction::function_reset() -> void {
    _pci->reset();
    abandon_in_flight();
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
    const auto free_slot = [&q] {
        return std::ranges::any_of(q.slots, [](const Slot& s) { return !s.busy; });
    };
    ring->set_notifications(false);
    for (std::size_t done = 0;; ++done) {
        if (done == _budget) {
            // Notifications stay off; the transport calls poll() for the rest.
            _pci->signal(index);
            q.signal = false;
            return true;
        }
        if (!free_slot()) {
            // Every slot is in the backend. Notifications stay off; the next
            // completion marks the queue pending and poll() continues.
            break;
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
        if (!serve(index, **next)) {
            return false;
        }
        if (_pci->queue(index) != ring) {
            return false;  // an inline completion failed the function
        }
    }
    _pci->signal(index);
    q.signal = false;
    return false;
}

auto VirtioBlkFunction::count(Status st) -> void {
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
}

auto VirtioBlkFunction::serve(std::uint16_t index, const virtio::Chain& chain) -> bool {
    virtio::SplitQueue* ring = _pci->queue(index);
    auto parsed = _parser.parse(chain.readable, chain.writable);
    std::uint32_t data_written = 0;
    Status st = Status::ok;
    std::span<std::byte> status_byte;
    if (!parsed) {
        const Rejection& r = parsed.error();
        if (r.error == ParseError::no_status_byte) {
            queue_error();
            return false;
        }
        st = status_for(r.error);
        status_byte = r.status;
    } else {
        const Request& req = *parsed;
        status_byte = req.status;
        switch (req.type) {
            case RequestType::in:
            case RequestType::out:
            case RequestType::flush: {
                Queue& q = _queues[index];
                const auto it =
                    std::ranges::find_if(q.slots, [](const Slot& s) { return !s.busy; });
                // process() only pops with a slot free.
                submit(index, static_cast<std::size_t>(it - q.slots.begin()), chain, req);
                return true;
            }
            case RequestType::get_id:
                data_written = do_get_id(req);
                break;
            default:
                st = Status::unsupp;  // the parser admits no other type
                break;
        }
    }
    complete(status_byte, st);
    count(st);
    // Bytes written into the chain: the data (GET_ID) and the status.
    if (!ring->push(chain.head, data_written + static_cast<std::uint32_t>(status_size))) {
        queue_error();
        return false;
    }
    _queues[index].signal = true;
    return true;
}

auto VirtioBlkFunction::submit(std::uint16_t index, std::size_t slot, const virtio::Chain& chain,
                               const Request& req) -> void {
    Queue& q = _queues[index];
    Slot& s = q.slots[slot];
    s.busy = true;
    s.abandoned = false;
    s.head = chain.head;
    s.type = req.type;
    s.unit = req.sector / (_parser.geometry().logical_block_size / sector_size);
    s.data_bytes = req.type == RequestType::in ? req.data_bytes : 0;
    s.writable.clear();
    for (std::size_t i = 0; i < chain.writable.size(); ++i) {
        s.writable.emplace_back(chain.writable_gpa[i], chain.writable[i].size());
    }
    ++_in_flight;

    // A completion that runs while _in_submit is set came back inside the
    // submit call; any other was parked. Completions of other requests only
    // run from the backend's poll(), never inside a submit.
    auto done = [this, index, slot](BackendResult r) {
        if (!_in_submit) {
            ++_counters.parked;
        }
        finish(index, slot, r);
    };
    struct InSubmit {
        bool& flag;
        explicit InSubmit(bool& f) : flag{f} { flag = true; }
        InSubmit(const InSubmit&) = delete;
        auto operator=(const InSubmit&) -> InSubmit& = delete;
        InSubmit(InSubmit&&) = delete;
        auto operator=(InSubmit&&) -> InSubmit& = delete;
        ~InSubmit() { flag = false; }
    } const in_submit{_in_submit};

    if (req.type == RequestType::flush) {
        _backend->submit_flush(std::move(done));
        return;
    }
    if (!q.cipher) {
        ++_counters.no_key;
        finish(index, slot, std::unexpected(BackendError::io));  // no key: no volume data
        return;
    }
    const std::uint64_t offset = req.sector * sector_size;
    const std::span<std::byte> buf = std::span{s.bounce}.first(req.data_bytes);
    if (req.type == RequestType::out) {
        // Copy once, so the guest cannot change the data between encrypting
        // and writing; the buffer holds ciphertext from here on.
        gather(req.out_data, buf);
        if (!q.cipher->encrypt(s.unit, buf, buf)) {
            finish(index, slot, std::unexpected(BackendError::io));
            return;
        }
        _backend->submit_write(offset, buf, std::move(done));
    } else {
        _backend->submit_read(offset, buf, std::move(done));
    }
}

auto VirtioBlkFunction::deliver(const Slot& s, std::span<const std::byte> data, Status st) -> bool {
    // Translate every writable buffer again first, so nothing is written
    // unless all of it can be.
    std::vector<std::span<std::byte>> spans;
    spans.reserve(s.writable.size());
    for (const auto& [gpa, len] : s.writable) {
        auto b = _memory->writable(gpa, len);
        if (!b) {
            return false;
        }
        spans.push_back(*b);
    }
    // The parser checked that the buffers hold data_bytes plus the status
    // byte. Without `data` (a failure) the data bytes are left alone.
    const std::size_t total = s.data_bytes + status_size;
    std::size_t at = 0;
    for (auto seg : spans) {
        for (auto& b : seg) {
            if (at < s.data_bytes) {
                if (!data.empty()) {
                    b = data[at];
                }
            } else if (at + 1 == total) {
                complete(std::span{&b, 1}, st);
            }
            ++at;
        }
    }
    return true;
}

auto VirtioBlkFunction::finish(std::uint16_t index, std::size_t slot, BackendResult result)
    -> void {
    Queue& q = _queues[index];
    Slot& s = q.slots[slot];
    --_in_flight;
    const auto release = [&s] {
        OPENSSL_cleanse(s.bounce.data(), s.bounce.size());
        s.busy = false;
        s.abandoned = false;
    };
    if (s.abandoned) {
        release();
        return;
    }
    q.pending = true;  // a slot is free: requests may be waiting for it

    Status st = result ? Status::ok : Status::ioerr;
    const std::span<std::byte> buf = std::span{s.bounce}.first(s.data_bytes);
    if (st == Status::ok && s.type == RequestType::in) {
        // The key may have been dropped while the read was in flight.
        if (!q.cipher || !q.cipher->decrypt(s.unit, buf, buf)) {
            st = Status::ioerr;
        }
    }
    // A failure owes the driver only its status byte.
    const bool delivered = deliver(
        s, st == Status::ok ? std::span<const std::byte>{buf} : std::span<const std::byte>{}, st);
    release();  // no plaintext left behind
    virtio::SplitQueue* ring = _pci->queue(index);
    if (!delivered || ring == nullptr) {
        queue_error();
        return;
    }
    count(st);
    const auto written =
        static_cast<std::uint32_t>((st == Status::ok ? s.data_bytes : 0) + status_size);
    if (!ring->push(s.head, written)) {
        queue_error();
        return;
    }
    q.signal = true;
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
