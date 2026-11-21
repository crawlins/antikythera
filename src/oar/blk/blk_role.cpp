// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/blk_role.hpp"

#include <format>
#include <limits>
#include <utility>

#include "oar/blk/file_backend.hpp"

namespace ak::oar::blk {

namespace {

namespace oar = helm::oar;

// The placeholder's whole "volume": one 4 KiB block nobody can read.
constexpr std::uint64_t placeholder_sectors = 8;
constexpr std::uint64_t placeholder_bytes = placeholder_sectors * sector_size;
constexpr std::string_view placeholder_serial = "akv-none";

// Every access fails: the placeholder never holds a key, so its requests
// never get this far, and if one did it would still reach nothing.
class NullBackend final : public SyncBlockBackend {
public:
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override {
        return placeholder_bytes;
    }
    [[nodiscard]] auto read(std::uint64_t /*offset*/, std::span<std::byte> /*out*/)
        -> std::expected<void, BackendError> override {
        return std::unexpected(BackendError::io);
    }
    [[nodiscard]] auto write(std::uint64_t /*offset*/, std::span<const std::byte> /*in*/)
        -> std::expected<void, BackendError> override {
        return std::unexpected(BackendError::io);
    }
    [[nodiscard]] auto flush() -> std::expected<void, BackendError> override {
        return std::unexpected(BackendError::io);
    }
};

auto on_flr(VirtioBlkFunction& f) -> std::function<void()> {
    return [fn = &f] { fn->function_reset(); };
}

}  // namespace

auto volume_serial(std::uint64_t volume_id) -> std::string {
    return std::format("akv-{:016x}", volume_id);
}

auto BlkRole::create(RoleConfig config, const std::vector<FunctionTransport*>& transports)
    -> std::expected<std::unique_ptr<BlkRole>, std::string> {
    if (transports.empty() || transports.size() > std::numeric_limits<oar::FunctionNumber>::max()) {
        return std::unexpected("need between 1 and 65535 functions");
    }
    if (!config.clock) {
        config.clock = [] { return RoleConfig::Clock::now(); };
    }
    std::unique_ptr<BlkRole> role{new BlkRole{std::move(config)}};
    role->_started = role->_config.clock();
    role->_slots.resize(transports.size());
    for (std::size_t i = 0; i < transports.size(); ++i) {
        Slot& s = role->_slots[i];
        s.transport = transports[i];
        if (s.transport == nullptr) {
            return std::unexpected(std::format("function {}: no transport", i));
        }
        const VolumeGeometry g{.capacity_sectors = placeholder_sectors,
                               .logical_block_size = sector_size,
                               .read_only = false,
                               .seg_max = role->_config.seg_max,
                               .max_transfer_bytes = role->_config.max_transfer_bytes};
        auto f =
            VirtioBlkFunction::create(role->params(g, placeholder_serial), s.transport->memory(),
                                      s.transport->interrupts(), std::make_unique<NullBackend>());
        if (!f) {
            return std::unexpected(std::format("function {}: {}", i, to_string(f.error())));
        }
        s.placeholder = std::move(*f);
        if (auto ok = s.transport->serve(s.placeholder->pci(), on_flr(*s.placeholder)); !ok) {
            return std::unexpected(std::format("function {}: {}", i, ok.error()));
        }
    }
    return role;
}

BlkRole::~BlkRole() = default;

auto BlkRole::params(const VolumeGeometry& geometry, std::string_view serial) const -> BlkParams {
    return BlkParams{.geometry = geometry,
                     .num_queues = _config.num_queues,
                     .queue_size = _config.queue_size,
                     .budget = _config.budget,
                     .serial = serial};
}

auto BlkRole::volume_path(std::uint64_t volume_id) const -> std::filesystem::path {
    return _config.volume_dir / std::format("vol-{:016x}.akv", volume_id);
}

auto BlkRole::slot(oar::FunctionNumber fn) -> Slot* {
    return fn < _slots.size() ? &_slots[fn] : nullptr;
}

auto BlkRole::slot_of_volume(std::uint64_t volume) -> Slot* {
    for (auto& s : _slots) {
        if (s.active && s.volume == volume) {
            return &s;
        }
    }
    return nullptr;
}

auto BlkRole::attached(oar::FunctionNumber fn) const -> std::optional<std::uint64_t> {
    if (fn >= _slots.size() || !_slots[fn].active) {
        return std::nullopt;
    }
    return _slots[fn].volume;
}

auto BlkRole::function(oar::FunctionNumber fn) -> VirtioBlkFunction* {
    Slot* s = slot(fn);
    return s == nullptr ? nullptr : s->active.get();
}

auto BlkRole::close(Slot& s) -> bool {
    if (!s.active) {
        return true;
    }
    s.active->drop_key();
    // The placeholder goes back first, so the transport never points at a
    // destroyed function.
    s.placeholder->function_reset();
    if (auto ok = s.transport->serve(s.placeholder->pci(), on_flr(*s.placeholder)); !ok) {
        return false;
    }
    s.active.reset();
    s.volume = 0;
    return true;
}

// ---- functions -------------------------------------------------------------

auto BlkRole::function_inventory() -> std::expected<oar::Inventory, oar::Status> {
    oar::Inventory inv{.role = oar::Role::blk, .vtep = {}, .functions = {}};
    for (std::size_t i = 0; i < _slots.size(); ++i) {
        inv.functions.push_back(
            {.fn = static_cast<oar::FunctionNumber>(i), .type = helm::FunctionType::blk_fn});
    }
    return inv;
}

auto BlkRole::prepare_function(const oar::PrepareFunction& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    const auto* cfg = std::get_if<oar::BlkConfig>(&request.config);
    if (request.type != helm::FunctionType::blk_fn || cfg == nullptr) {
        return oar::Status::wrong_type;
    }
    if (s->active || slot_of_volume(cfg->volume_id) != nullptr) {
        return oar::Status::busy;
    }
    auto backend = FileBackend::open(volume_path(cfg->volume_id));
    if (!backend) {
        return oar::Status::failed;
    }
    const VolumeMetadata& m = (*backend)->metadata();
    if (m.volume_id != cfg->volume_id || m.owner_vm != request.vm_id) {
        return oar::Status::failed;
    }
    const VolumeGeometry g{.capacity_sectors = m.capacity_sectors,
                           .logical_block_size = m.logical_block_size,
                           .read_only = false,
                           .seg_max = _config.seg_max,
                           .max_transfer_bytes = _config.max_transfer_bytes};
    const std::string serial = volume_serial(cfg->volume_id);
    auto f = VirtioBlkFunction::create(params(g, serial), s->transport->memory(),
                                       s->transport->interrupts(), std::move(*backend));
    if (!f) {
        return oar::Status::failed;
    }
    // Until helm's key arrives (after the VMM opened the function), the
    // guest's requests wait in the rings.
    (*f)->await_key();
    if (auto ok = s->transport->serve((*f)->pci(), on_flr(**f)); !ok) {
        // Back to the placeholder; if even that fails the transport is lost.
        static_cast<void>(s->transport->serve(s->placeholder->pci(), on_flr(*s->placeholder)));
        return oar::Status::failed;
    }
    s->active = std::move(*f);
    s->volume = cfg->volume_id;
    return oar::Status::ok;
}

auto BlkRole::clean_function(const oar::CleanFunction& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    if (request.action != helm::CleaningAction::drop_volume_key) {
        return oar::Status::wrong_type;
    }
    return close(*s) ? oar::Status::ok : oar::Status::failed;
}

auto BlkRole::deliver_key(const oar::DeliverKey& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    if (!s->active || s->volume != request.volume_id) {
        return oar::Status::busy;
    }
    // The span views helm's message, which OarEndpoint wipes after this
    // returns; the function copies it into its key slot now.
    auto ok = s->active->deliver_key(request.key);
    if (!ok) {
        return ok.error() == KeyError::occupied ? oar::Status::busy : oar::Status::failed;
    }
    return oar::Status::ok;
}

auto BlkRole::drop_key(const oar::DropKey& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    if (s->active) {
        if (s->volume != request.volume_id) {
            return oar::Status::busy;
        }
        s->active->drop_key();
    }
    return oar::Status::ok;
}

auto BlkRole::map_update(std::span<const std::byte> /*frame*/) -> oar::Status {
    return oar::Status::unsupported;
}

auto BlkRole::health() -> std::expected<oar::Health, oar::Status> {
    const auto up = std::chrono::duration_cast<std::chrono::seconds>(_config.clock() - _started);
    const auto secs = static_cast<std::uint64_t>(std::max<std::int64_t>(0, up.count()));
    return oar::Health{.state = oar::HealthState::ok,
                       .fault_code = 0,
                       .uptime_seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                           secs, std::numeric_limits<std::uint32_t>::max()))};
}

auto BlkRole::poll() -> bool {
    bool more = false;
    for (auto& s : _slots) {
        if (s.active) {
            // The function itself, not pci().poll(): completions of requests
            // abandoned by a reset must run even while the driver is not live.
            more = s.active->poll() || more;
        }
    }
    return more;
}

auto BlkRole::wake_fds() const -> std::vector<int> {
    std::vector<int> fds;
    for (const auto& s : _slots) {
        if (s.active && s.active->wake_fd() >= 0) {
            fds.push_back(s.active->wake_fd());
        }
    }
    return fds;
}

// ---- volumes ---------------------------------------------------------------

auto BlkRole::create_volume(const oar::CreateVolume& request) -> oar::Status {
    VolumeMetadata m{.volume_id = request.volume_id,
                     .owner_vm = request.owner_vm,
                     .capacity_sectors = request.capacity_sectors,
                     .logical_block_size = request.block_size,
                     .wrapped_key = {request.wrapped_key.begin(), request.wrapped_key.end()}};
    // create() never overwrites: an existing volume file is refused.
    return FileBackend::create(volume_path(request.volume_id), m) ? oar::Status::ok
                                                                  : oar::Status::failed;
}

auto BlkRole::delete_volume(const oar::DeleteVolume& request) -> oar::Status {
    // helm crypto-erased the key first; a function still holding the volume
    // (its VM was destroyed and the function not yet cleaned) lets go now.
    if (Slot* s = slot_of_volume(request.volume_id); s != nullptr && !close(*s)) {
        return oar::Status::failed;
    }
    auto erased = FileBackend::erase(volume_path(request.volume_id));
    if (!erased && erased.error().error != FileError::not_found) {
        return oar::Status::failed;
    }
    // Already gone counts as done: a retried delete must not fail.
    return oar::Status::ok;
}

auto BlkRole::rewrap_volume(const oar::RewrapVolume& request) -> oar::Status {
    if (slot_of_volume(request.volume_id) != nullptr) {
        return oar::Status::busy;
    }
    auto backend = FileBackend::open(volume_path(request.volume_id));
    if (!backend) {
        return oar::Status::failed;
    }
    return (*backend)->rewrap(request.owner_vm, request.wrapped_key) ? oar::Status::ok
                                                                     : oar::Status::failed;
}

}  // namespace ak::oar::blk
