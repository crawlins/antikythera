// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/command_router.hpp"

#include <algorithm>
#include <utility>
#include <variant>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

constexpr std::size_t slot_type_offset = 0x06;

// The message type in a slot header, read without decoding the slot, so a
// malformed command's outcome can still name what it claimed to be.
auto slot_type(const proto::Slot& slot) noexcept -> std::uint16_t {
    wire::Reader r{std::span<const std::byte>{slot}.subspan(slot_type_offset)};
    return r.le16().value_or(0);
}

auto to_mailbox_slot(const proto::Slot& slot) noexcept -> mailbox::Slot {
    mailbox::Slot out{};
    std::ranges::copy(slot, out.begin());
    return out;
}

auto link_status(const LinkError& e) noexcept -> mailbox::Status {
    switch (e.code) {
        case LinkErrc::timed_out:
            return mailbox::Status::timed_out;
        case LinkErrc::refused:
            switch (e.status) {
                case oar::Status::unknown_function:
                case oar::Status::wrong_type:
                    return mailbox::Status::unknown_device;
                case oar::Status::busy:
                    return mailbox::Status::conflict;
                case oar::Status::unsupported:
                    return mailbox::Status::unsupported;
                default:
                    return mailbox::Status::internal_error;
            }
        default:
            return mailbox::Status::internal_error;
    }
}

auto succeeded(mailbox::Status s) noexcept -> bool {
    return s == mailbox::Status::ok || s == mailbox::Status::accepted;
}

auto to_proto(FunctionType t) noexcept -> proto::FunctionType {
    return static_cast<proto::FunctionType>(t);
}

auto to_proto(FunctionState s) noexcept -> proto::FunctionState {
    return static_cast<proto::FunctionState>(s);
}

auto function_id(const mailbox::DeviceRef& d) noexcept -> FunctionId {
    return make_function_id(d.slot, d.function);
}

auto command_code(mailbox::Type t) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(t);
}

auto status_code(mailbox::Status s) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(s);
}

// 512-byte sectors in a CREATE_VOLUME size (1 GiB = 2^21 sectors).
constexpr unsigned gib_sector_shift = 21;

}  // namespace

// ---- OarLinkPort -----------------------------------------------------------

auto OarLinkPort::prepare_function(const oar::PrepareFunction& request)
    -> std::expected<void, LinkError> {
    return _link->prepare_function(request);
}

auto OarLinkPort::clean_function(const oar::CleanFunction& request)
    -> std::expected<void, LinkError> {
    return _link->clean_function(request);
}

auto OarLinkPort::group_policy(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    return _link->group_policy(frame);
}

auto OarLinkPort::group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> {
    return _link->group_usage();
}

auto OarLinkPort::deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key)
    -> std::expected<void, LinkError> {
    return _link->deliver_key(fn, volume, std::move(key));
}

auto OarLinkPort::drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> {
    return _link->drop_key(request);
}

auto OarLinkPort::create_volume(const oar::CreateVolume& request)
    -> std::expected<void, LinkError> {
    return _link->create_volume(request);
}

auto OarLinkPort::delete_volume(const oar::DeleteVolume& request)
    -> std::expected<void, LinkError> {
    return _link->delete_volume(request);
}

auto OarLinkPort::rewrap_volume(const oar::RewrapVolume& request)
    -> std::expected<void, LinkError> {
    return _link->rewrap_volume(request);
}

// ---- CommandRouter ---------------------------------------------------------

CommandRouter::CommandRouter(RouterConfig config, DevicePool& pool, KeyStore& keys, HostPort& host,
                             ReportSink& reports, AuditLog& audit)
    : _config{std::move(config)},
      _pool{&pool},
      _keys{&keys},
      _host{&host},
      _reports{&reports},
      _audit{&audit},
      _last_seq{_config.last_seq} {
    if (!_config.clock) {
        _config.clock = [] { return Clock::now(); };
    }
}

auto CommandRouter::now() const -> Clock::time_point {
    return _config.clock();
}

auto CommandRouter::audit(const AuditRecord& record) -> bool {
    if (!_audit->append(record)) {
        ++_stats.audit_failures;
        return false;
    }
    return true;
}

auto CommandRouter::port_for(std::uint8_t slot) -> OarPort* {
    const auto it = _ports.find(slot);
    return it == _ports.end() ? nullptr : it->second;
}

auto CommandRouter::storage_slot() const -> std::optional<std::uint8_t> {
    for (const auto& [slot, role] : _roles) {
        if (role == oar::Role::blk && _ports.contains(slot)) {
            return slot;
        }
    }
    return std::nullopt;
}

// ---- slots -----------------------------------------------------------------

auto CommandRouter::add_slot(std::uint8_t slot, OarPort& port, const oar::Inventory& inventory)
    -> void {
    _ports[slot] = &port;
    _roles[slot] = inventory.role;
    for (const auto& entry : inventory.functions) {
        const auto id = make_function_id(slot, entry.fn);
        // A function already known (the slot came back after a power
        // cycle) keeps its state; slot_power_cycled handles it.
        if (_pool->add(id, entry.type)) {
            start_cleaning(id);
        }
    }
}

auto CommandRouter::slot_power_cycled(std::uint8_t slot) -> void {
    for (const auto& info : _pool->all()) {
        if (slot_of(info.id) == slot && info.state == FunctionState::faulted &&
            pool_event(info.id, PoolEvent::power_cycle_done)) {
            start_cleaning(info.id);
        }
    }
}

// ---- envelopes -------------------------------------------------------------

auto CommandRouter::on_envelope(const proto::Envelope& envelope) -> void {
    const auto seq = proto::slot_seq(envelope.slot);
    const auto type = static_cast<mailbox::Type>(slot_type(envelope.slot));

    if (seq <= _last_seq) {
        if (const auto it = _history.find(seq); it != _history.end()) {
            ++_stats.duplicates;
            _reports->report(it->second);
            return;
        }
        const bool pending = (_in_flight && _in_flight->seq == seq) ||
                             std::ranges::any_of(_queue, [seq](const proto::Envelope& e) {
                                 return proto::slot_seq(e.slot) == seq;
                             });
        if (pending) {
            ++_stats.duplicates;
            return;
        }
        // Not recorded in the history: the sequence number belongs to some
        // other (older) command.
        ++_stats.refused;
        audit(AuditRecord::of(AuditEvent::command_refused)
                  .with_seq(seq)
                  .with_command(command_code(type))
                  .with_status(status_code(mailbox::Status::stale_sequence)));
        _reports->report(Outcome{.in_reply_to = seq,
                                 .command = command_code(type),
                                 .status = proto::CommandStatus::stale_sequence,
                                 .payload = {}});
        return;
    }
    if (_queue.size() >= _config.max_queued) {
        // Not accepted: the controller may send this sequence number again.
        ++_stats.refused;
        audit(AuditRecord::of(AuditEvent::command_refused)
                  .with_seq(seq)
                  .with_command(command_code(type))
                  .with_status(status_code(mailbox::Status::insufficient_resources)));
        _reports->report(Outcome{.in_reply_to = seq,
                                 .command = command_code(type),
                                 .status = proto::CommandStatus::insufficient_resources,
                                 .payload = {}});
        return;
    }
    _last_seq = seq;
    _queue.push_back(envelope);
    audit(AuditRecord::of(AuditEvent::command_received)
              .with_seq(seq)
              .with_command(command_code(type)));
    pump();
}

auto CommandRouter::pump() -> void {
    while (!_in_flight && !_queue.empty()) {
        const auto envelope = _queue.front();
        _queue.pop_front();
        dispatch(envelope);
    }
}

auto CommandRouter::dispatch(const proto::Envelope& envelope) -> void {
    const auto seq = proto::slot_seq(envelope.slot);
    const auto claimed = static_cast<mailbox::Type>(slot_type(envelope.slot));
    const auto slot = to_mailbox_slot(envelope.slot);

    const auto msg = mailbox::decode(slot);
    if (!msg || !mailbox::is_command(msg->header.type)) {
        refuse(seq, claimed, mailbox::Status::malformed);
        return;
    }
    const auto body = mailbox::decode_body(*msg);
    if (!body) {
        refuse(seq, claimed,
               body.error() == mailbox::BodyError::reserved_type ? mailbox::Status::unsupported
                                                                 : mailbox::Status::malformed);
        return;
    }

    Undo undo;
    if (auto ok = prepare(seq, *body, undo); !ok) {
        compensate(seq, undo);
        refuse(seq, claimed, ok.error());
        return;
    }
    // The relay record comes first; if it cannot be written the command is
    // not relayed.
    if (!audit(AuditRecord::of(AuditEvent::command_relayed)
                   .with_seq(seq)
                   .with_command(command_code(claimed)))) {
        compensate(seq, undo);
        refuse(seq, claimed, mailbox::Status::internal_error);
        return;
    }
    if (!_host->post_command(slot)) {
        compensate(seq, undo);
        refuse(seq, claimed, mailbox::Status::internal_error);
        return;
    }
    ++_stats.relayed;
    _in_flight = InFlight{
        .seq = seq, .body = *body, .undo = undo, .deadline = now() + _config.command_timeout};
}

auto CommandRouter::reserve(VmId vm, const mailbox::DeviceRef& device, Undo& undo)
    -> std::expected<FunctionId, mailbox::Status> {
    const auto id = function_id(device);
    const auto info = _pool->find(id);
    if (!info || info->type != static_cast<FunctionType>(device.type) ||
        port_for(device.slot) == nullptr) {
        return std::unexpected(mailbox::Status::unknown_device);
    }
    if (!assign(id, vm)) {
        return std::unexpected(mailbox::Status::conflict);
    }
    undo.reserved = id;
    return id;
}

auto CommandRouter::assign(FunctionId id, VmId vm) -> bool {
    const auto before = _pool->find(id);
    if (!before || !_pool->assign(id, vm)) {
        return false;
    }
    report_transition(id, before->state, *_pool->find(id), vm);
    return true;
}

auto CommandRouter::prepare(std::uint64_t seq, const mailbox::Body& body, Undo& undo)
    -> std::expected<void, mailbox::Status> {
    using mailbox::Status;

    if (const auto* c = std::get_if<mailbox::CreateVm>(&body)) {
        if (_vms.contains(c->vm_id)) {
            return std::unexpected(Status::conflict);
        }
        if (auto k = _keys->create_vm_key(c->vm_id); !k) {
            return std::unexpected(k.error() == KeyError::duplicate_vm ? Status::conflict
                                                                       : Status::internal_error);
        }
        undo.created_vm_key = c->vm_id;
        audit(AuditRecord::of(AuditEvent::vm_key_created).with_seq(seq).with_vm(c->vm_id));
        return {};
    }

    if (const auto* a = std::get_if<mailbox::AttachDevice>(&body)) {
        const auto type = static_cast<FunctionType>(a->device.type);
        oar::FunctionConfig config;
        if (type == FunctionType::nic_vf) {
            // decode_attach_device has checked these (non-zero VNI and NIC
            // ID, locally administered unicast MAC).
            config = oar::NicConfig{.nic_id = a->nic_id, .vni = a->vni, .mac = a->mac};
        }
        auto reserved = reserve(a->vm_id, a->device, undo);
        if (!reserved) {
            return std::unexpected(reserved.error());
        }
        auto ok =
            port_for(a->device.slot)
                ->prepare_function(
                    {.fn = a->device.function, .type = type, .vm_id = a->vm_id, .config = config});
        if (!ok) {
            return std::unexpected(link_status(ok.error()));
        }
        return {};
    }

    if (const auto* d = std::get_if<mailbox::DetachDevice>(&body)) {
        const auto info = _pool->find(function_id(d->device));
        if (!info || info->type != static_cast<FunctionType>(d->device.type)) {
            return std::unexpected(Status::unknown_device);
        }
        if (info->state != FunctionState::assigned || info->owner != d->vm_id) {
            return std::unexpected(Status::conflict);
        }
        return {};
    }

    if (const auto* c = std::get_if<mailbox::CreateVolume>(&body);
        c != nullptr && c->image_store != 0) {
        if (_volumes.contains(c->volume_id) || _keys->owner(c->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        if (!_keys->find_vm_key(c->owner_vm)) {
            return std::unexpected(Status::unknown_vm);
        }
        const auto slot = storage_slot();
        if (!slot) {
            return std::unexpected(Status::insufficient_resources);
        }
        auto stored = port_for(*slot)->create_volume(
            {.volume_id = c->volume_id,
             .owner_vm = c->owner_vm,
             .capacity_sectors = std::uint64_t{c->size_gib} << gib_sector_shift,
             .block_size = oar::sector_size,
             .wrapped_key = {},
             .image_store = c->image_store,
             .image_name = c->image_name});
        if (!stored) {
            return std::unexpected(link_status(stored.error()));
        }
        undo.stored_volume = StoredVolume{.volume = c->volume_id, .slot = *slot};
        return {};
    }

    if (const auto* c = std::get_if<mailbox::CreateVolume>(&body)) {
        if (_volumes.contains(c->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        if (auto k = _keys->create_volume_key(c->volume_id, c->owner_vm); !k) {
            switch (k.error()) {
                case KeyError::unknown_vm:
                    return std::unexpected(Status::unknown_vm);
                case KeyError::duplicate_volume:
                    return std::unexpected(Status::conflict);
                default:
                    return std::unexpected(Status::internal_error);
            }
        }
        undo.created_volume_key = c->volume_id;
        audit(AuditRecord::of(AuditEvent::volume_key_created)
                  .with_seq(seq)
                  .with_vm(c->owner_vm)
                  .with_volume(c->volume_id));
        const auto slot = storage_slot();
        if (!slot) {
            return std::unexpected(Status::insufficient_resources);
        }
        const auto wrapped = _keys->find_volume_key(c->volume_id);
        if (!wrapped) {
            return std::unexpected(Status::internal_error);
        }
        auto stored = port_for(*slot)->create_volume(
            {.volume_id = c->volume_id,
             .owner_vm = c->owner_vm,
             .capacity_sectors = std::uint64_t{c->size_gib} << gib_sector_shift,
             .block_size = oar::sector_size,
             .wrapped_key = wrapped->key.bytes(),
             .image_store = 0,
             .image_name = {}});
        if (!stored) {
            // Not marked for undo: a refused create (the volume exists on
            // the media, say) must not be answered by erasing it.
            return std::unexpected(link_status(stored.error()));
        }
        undo.stored_volume = StoredVolume{.volume = c->volume_id, .slot = *slot};
        return {};
    }

    if (const auto* d = std::get_if<mailbox::DeleteVolume>(&body)) {
        if (!volume_owner(d->volume_id)) {
            return std::unexpected(Status::unknown_volume);
        }
        if (_attached.contains(d->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        return {};
    }

    if (const auto* a = std::get_if<mailbox::AttachVolume>(&body)) {
        const auto owner = volume_owner(a->volume_id);
        if (!owner) {
            return std::unexpected(Status::unknown_volume);
        }
        if (*owner != a->vm_id || _attached.contains(a->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        // Only the board that stores the volume can serve it.
        if (const auto v = _volumes.find(a->volume_id);
            v != _volumes.end() && v->second.slot != a->device.slot) {
            return std::unexpected(Status::conflict);
        }
        auto reserved = reserve(a->vm_id, a->device, undo);
        if (!reserved) {
            return std::unexpected(reserved.error());
        }
        auto* port = port_for(a->device.slot);
        auto ok = port->prepare_function({.fn = a->device.function,
                                          .type = FunctionType::blk_fn,
                                          .vm_id = a->vm_id,
                                          .config = oar::BlkConfig{.volume_id = a->volume_id}});
        if (!ok) {
            return std::unexpected(link_status(ok.error()));
        }
        // The key goes on commit, after the VMM has opened (and reset) the
        // function. Its cleaning, should the attach fail, closes the volume.
        return {};
    }

    if (const auto* d = std::get_if<mailbox::DetachVolume>(&body)) {
        if (!volume_owner(d->volume_id)) {
            return std::unexpected(Status::unknown_volume);
        }
        const auto id = function_id(d->device);
        const auto it = _attached.find(d->volume_id);
        const auto info = _pool->find(id);
        if (it == _attached.end() || it->second != id || !info ||
            info->state != FunctionState::assigned || info->owner != d->vm_id) {
            return std::unexpected(Status::conflict);
        }
        return {};
    }

    if (const auto* r = std::get_if<mailbox::RewrapVolume>(&body)) {
        if (is_image_volume(r->volume_id)) {
            return std::unexpected(Status::unsupported);  // no key to rewrap (task 15)
        }
        const auto owner = _keys->owner(r->volume_id);
        if (!owner) {
            return std::unexpected(Status::unknown_volume);
        }
        if (*owner != r->from_vm || _attached.contains(r->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        if (!_keys->find_vm_key(r->to_vm)) {
            return std::unexpected(Status::unknown_vm);
        }
        return {};
    }

    // DESTROY_VM, LIST_VMS, VM_STATUS, CREATE_NETWORK, DELETE_NETWORK: hull
    // decides; helm commits on its answer.
    return {};
}

auto CommandRouter::compensate(std::uint64_t seq, Undo& undo) -> void {
    if (undo.stored_volume) {
        auto* port = port_for(undo.stored_volume->slot);
        if (port == nullptr || !port->delete_volume({.volume_id = undo.stored_volume->volume})) {
            ++_stats.storage_failures;
        }
    }
    if (undo.reserved && pool_event(*undo.reserved, PoolEvent::attach_failed)) {
        start_cleaning(*undo.reserved);
    }
    if (undo.created_volume_key && _keys->destroy_volume_key(*undo.created_volume_key)) {
        audit(AuditRecord::of(AuditEvent::volume_key_destroyed)
                  .with_seq(seq)
                  .with_volume(*undo.created_volume_key));
    }
    if (undo.created_vm_key) {
        if (auto erased = _keys->destroy_vm_key(*undo.created_vm_key)) {
            audit(AuditRecord::of(AuditEvent::vm_key_destroyed)
                      .with_seq(seq)
                      .with_vm(*undo.created_vm_key)
                      .with_count(erased->size()));
        }
    }
    undo = Undo{};
}

auto CommandRouter::commit(std::uint64_t seq, const mailbox::Body& body, const Undo& undo) -> void {
    if (const auto* c = std::get_if<mailbox::CreateVm>(&body)) {
        _vms[c->vm_id] = Vm{.vcpus = c->vcpus, .memory_mib = c->memory_mib};
    } else if (const auto* d = std::get_if<mailbox::DestroyVm>(&body)) {
        for (const auto id : _pool->held_by(d->vm_id)) {
            if (_pool->find(id)->state == FunctionState::assigned) {
                (void)release(id, d->vm_id);
            }
        }
        std::erase_if(_attached,
                      [&](const auto& entry) { return volume_owner(entry.first) == d->vm_id; });
        if (!d->persist_volumes) {
            // Image volumes have no key to erase: only their descriptors go.
            std::vector<VolumeId> images;
            for (const auto& [id, volume] : _volumes) {
                if (volume.image && volume.owner == d->vm_id) {
                    images.push_back(id);
                }
            }
            for (const auto volume : images) {
                erase_volume(volume);
                _volumes.erase(volume);
            }
            if (auto erased = _keys->destroy_vm_key(d->vm_id)) {
                audit(AuditRecord::of(AuditEvent::vm_key_destroyed)
                          .with_seq(seq)
                          .with_vm(d->vm_id)
                          .with_count(erased->size()));
                for (const auto volume : *erased) {
                    erase_volume(volume);
                    _volumes.erase(volume);
                }
            }
        }
        _vms.erase(d->vm_id);
    } else if (const auto* dd = std::get_if<mailbox::DetachDevice>(&body)) {
        if (!release(function_id(dd->device), dd->vm_id)) {
            ++_stats.inconsistencies;
        }
    } else if (const auto* cv = std::get_if<mailbox::CreateVolume>(&body)) {
        _volumes[cv->volume_id] =
            Volume{.owner = cv->owner_vm,
                   .size_gib = cv->size_gib,
                   .slot = undo.stored_volume ? undo.stored_volume->slot : std::uint8_t{0},
                   .image = cv->image_store != 0};
    } else if (const auto* dv = std::get_if<mailbox::DeleteVolume>(&body)) {
        // An image volume has nothing to crypto-erase: each attachment's
        // key died with the attachment.
        if (!is_image_volume(dv->volume_id)) {
            if (_keys->destroy_volume_key(dv->volume_id)) {
                audit(AuditRecord::of(AuditEvent::volume_key_destroyed)
                          .with_seq(seq)
                          .with_volume(dv->volume_id));
            } else {
                ++_stats.inconsistencies;
            }
        }
        erase_volume(dv->volume_id);
        _volumes.erase(dv->volume_id);
    } else if (const auto* av = std::get_if<mailbox::AttachVolume>(&body)) {
        _attached[av->volume_id] = function_id(av->device);
        deliver_volume_key(seq, *av);
    } else if (const auto* xv = std::get_if<mailbox::DetachVolume>(&body)) {
        if (!release(function_id(xv->device), xv->vm_id)) {
            ++_stats.inconsistencies;
        }
        _attached.erase(xv->volume_id);
    } else if (const auto* r = std::get_if<mailbox::RewrapVolume>(&body)) {
        if (_keys->rewrap(r->volume_id, r->to_vm)) {
            audit(AuditRecord::of(AuditEvent::volume_key_rewrapped)
                      .with_seq(seq)
                      .with_vm(r->to_vm)
                      .with_volume(r->volume_id));
            auto it = _volumes.find(r->volume_id);
            if (it != _volumes.end()) {
                it->second.owner = r->to_vm;
            }
            const auto wrapped = _keys->find_volume_key(r->volume_id);
            auto* port = it == _volumes.end() ? nullptr : port_for(it->second.slot);
            if (!wrapped || port == nullptr ||
                !port->rewrap_volume({.volume_id = r->volume_id,
                                      .owner_vm = r->to_vm,
                                      .wrapped_key = wrapped->key.bytes()})) {
                ++_stats.storage_failures;
            }
        } else {
            ++_stats.inconsistencies;
        }
    } else if (const auto* cn = std::get_if<mailbox::CreateNetwork>(&body)) {
        _networks.try_emplace(cn->vni, 0);
    } else if (const auto* dn = std::get_if<mailbox::DeleteNetwork>(&body)) {
        _networks.erase(dn->vni);
    }
}

auto CommandRouter::deliver_volume_key(std::uint64_t seq, const mailbox::AttachVolume& attach)
    -> void {
    const auto id = function_id(attach.device);
    auto* port = port_for(attach.device.slot);
    // An image volume's key exists only for this attachment.
    auto key = is_image_volume(attach.volume_id)
                   ? _keys->create_ephemeral_key()
                   : _keys->unwrap_volume_key(attach.volume_id, attach.vm_id);
    bool delivered = false;
    if (port != nullptr && key) {
        delivered = port->deliver_key(attach.device.function, attach.volume_id, std::move(*key))
                        .has_value();
    }
    const auto record = AuditRecord::of(delivered ? AuditEvent::volume_key_delivered
                                                  : AuditEvent::volume_key_delivery_failed)
                            .with_seq(seq)
                            .with_vm(attach.vm_id)
                            .with_volume(attach.volume_id)
                            .with_function(id);
    audit(record);
    if (!delivered) {
        ++_stats.key_delivery_failures;
        _reports->report(proto::HostFaultReport{.code = proto::FaultCode::device_lost,
                                                .slot = attach.device.slot,
                                                .detail = attach.volume_id});
    }
}

auto CommandRouter::volume_owner(VolumeId volume) const -> std::optional<VmId> {
    if (const auto it = _volumes.find(volume); it != _volumes.end() && it->second.image) {
        return it->second.owner;
    }
    return _keys->owner(volume);
}

auto CommandRouter::is_image_volume(VolumeId volume) const -> bool {
    const auto it = _volumes.find(volume);
    return it != _volumes.end() && it->second.image;
}

auto CommandRouter::erase_volume(VolumeId volume) -> void {
    const auto it = _volumes.find(volume);
    auto* port = it == _volumes.end() ? nullptr : port_for(it->second.slot);
    if (port == nullptr || !port->delete_volume({.volume_id = volume})) {
        ++_stats.storage_failures;
    }
}

auto CommandRouter::refuse(std::uint64_t seq, mailbox::Type command, mailbox::Status status)
    -> void {
    ++_stats.refused;
    audit(AuditRecord::of(AuditEvent::command_refused)
              .with_seq(seq)
              .with_command(command_code(command))
              .with_status(status_code(status)));
    finish(seq, command, status);
}

auto CommandRouter::finish(std::uint64_t seq, mailbox::Type command, mailbox::Status status,
                           std::span<const std::byte> payload) -> void {
    Outcome outcome{.in_reply_to = seq,
                    .command = command_code(command),
                    .status = static_cast<proto::CommandStatus>(status),
                    .payload = {payload.begin(), payload.end()}};
    _history.insert_or_assign(seq, outcome);
    while (_history.size() > _config.outcome_history) {
        _history.erase(_history.begin());
    }
    _reports->report(std::move(outcome));
}

// ---- hull ------------------------------------------------------------------

auto CommandRouter::on_host_slot(const mailbox::Slot& slot) -> void {
    const auto msg = mailbox::decode(slot);
    if (!msg || mailbox::is_command(msg->header.type)) {
        ++_stats.stray_messages;
        return;
    }
    const auto body = mailbox::decode_body(*msg);
    if (!body) {
        ++_stats.stray_messages;
        return;
    }
    if (std::holds_alternative<mailbox::Response>(*body)) {
        on_response(*msg);
    } else {
        on_event(*body);
    }
}

auto CommandRouter::on_response(const mailbox::Message& msg) -> void {
    const auto rsp = std::get<mailbox::Response>(*mailbox::decode_body(msg));
    if (_in_flight && rsp.in_reply_to == _in_flight->seq &&
        rsp.command == mailbox::type_of(_in_flight->body)) {
        auto done = std::move(*_in_flight);
        _in_flight.reset();
        audit(AuditRecord::of(AuditEvent::command_outcome)
                  .with_seq(done.seq)
                  .with_command(command_code(rsp.command))
                  .with_status(status_code(rsp.status)));
        if (succeeded(rsp.status)) {
            commit(done.seq, done.body, done.undo);
        } else {
            compensate(done.seq, done.undo);
        }
        finish(done.seq, rsp.command, rsp.status, rsp.payload_bytes());
        pump();
        return;
    }
    ++_stats.stray_messages;
    if (_timed_out.erase(rsp.in_reply_to) != 0) {
        audit(AuditRecord::of(AuditEvent::late_response)
                  .with_seq(rsp.in_reply_to)
                  .with_command(command_code(rsp.command))
                  .with_status(status_code(rsp.status)));
    }
}

auto CommandRouter::on_event(const mailbox::Body& body) -> void {
    if (const auto* r = std::get_if<mailbox::DeviceReleased>(&body)) {
        const auto id = function_id(r->device);
        const auto info = _pool->find(id);
        if (!info || info->owner != r->vm_id) {
            ++_stats.inconsistencies;
            return;
        }
        // hull may reset a function before helm has processed the response
        // that released it (DESTROY_VM, or the VM died): hull is the
        // authority on what the VM still holds, so release it first.
        if (info->state == FunctionState::assigned && !release(id, r->vm_id)) {
            ++_stats.inconsistencies;
            return;
        }
        _deadlines.erase(id);
        if (r->reset == mailbox::ResetResult::ok) {
            if (pool_event(id, PoolEvent::device_released)) {
                start_cleaning(id);
            }
        } else {
            (void)pool_event(id, PoolEvent::reset_failed);
        }
    } else if (const auto* s = std::get_if<mailbox::ScrubDone>(&body)) {
        const auto id = function_id(s->device);
        _deadlines.erase(id);
        if (!pool_event(id, s->result == mailbox::ScrubResult::ok ? PoolEvent::scrub_done
                                                                  : PoolEvent::clean_failed)) {
            ++_stats.inconsistencies;
        }
    } else if (const auto* e = std::get_if<mailbox::VmExited>(&body)) {
        _reports->report(
            proto::VmExitedReport{.vm_id = e->vm_id,
                                  .exit_status = e->exit_status,
                                  .reason = static_cast<proto::ExitReason>(e->reason)});
    } else if (const auto* f = std::get_if<mailbox::HostFault>(&body)) {
        _reports->report(proto::HostFaultReport{
            .code = static_cast<proto::FaultCode>(f->code), .slot = f->slot, .detail = f->detail});
    }
}

auto CommandRouter::on_map_applied(std::uint32_t vni, std::uint64_t map_version) -> void {
    _networks[vni] = map_version;
    _reports->report(proto::MapApplied{.vni = vni, .map_version = map_version});
}

auto CommandRouter::poll() -> void {
    const auto t = now();
    if (_in_flight && t >= _in_flight->deadline) {
        const auto seq = _in_flight->seq;
        const auto command = mailbox::type_of(_in_flight->body);
        _in_flight.reset();
        ++_stats.timed_out;
        _timed_out.insert(seq);
        while (_timed_out.size() > _config.outcome_history) {
            _timed_out.erase(_timed_out.begin());
        }
        audit(AuditRecord::of(AuditEvent::command_timed_out)
                  .with_seq(seq)
                  .with_command(command_code(command)));
        finish(seq, command, mailbox::Status::timed_out);
        pump();
    }
    for (auto it = _deadlines.begin(); it != _deadlines.end();) {
        if (t < it->second) {
            ++it;
            continue;
        }
        const auto id = it->first;
        it = _deadlines.erase(it);
        (void)pool_event(id, PoolEvent::timed_out);
    }
}

// ---- pool ------------------------------------------------------------------

auto CommandRouter::pool_event(FunctionId id, PoolEvent event) -> bool {
    const auto before = _pool->find(id);
    if (!before || !_pool->apply(id, event)) {
        return false;
    }
    report_transition(id, before->state, *_pool->find(id), before->owner);
    return true;
}

auto CommandRouter::release(FunctionId id, VmId vm) -> bool {
    const auto before = _pool->find(id);
    if (!before || !_pool->release(id, vm)) {
        return false;
    }
    report_transition(id, before->state, *_pool->find(id), vm);
    _deadlines[id] = now() + _config.release_timeout;
    return true;
}

auto CommandRouter::start_cleaning(FunctionId id) -> void {
    const auto info = _pool->find(id);
    if (!info || info->state != FunctionState::cleaning) {
        return;
    }
    if (is_gpu(info->type)) {
        // GPU memory is scrubbed through hull (scrubber or manager VM);
        // SCRUB_DONE finishes it.
        _deadlines[id] = now() + _config.clean_timeout;
        return;
    }
    auto* port = port_for(slot_of(id));
    if (port == nullptr) {
        (void)pool_event(id, PoolEvent::clean_failed);
        return;
    }
    const auto ok =
        port->clean_function({.fn = function_number_of(id), .action = cleaning_action(info->type)});
    if (info->type == FunctionType::blk_fn) {
        audit(AuditRecord::of(AuditEvent::volume_key_dropped).with_function(id));
    }
    if (ok) {
        (void)pool_event(id, PoolEvent::clean_done);
    } else {
        (void)pool_event(id, ok.error().code == LinkErrc::timed_out ? PoolEvent::timed_out
                                                                    : PoolEvent::clean_failed);
    }
}

auto CommandRouter::report_transition(FunctionId id, FunctionState from, const FunctionInfo& after,
                                      std::optional<VmId> vm) -> void {
    _reports->report(proto::PoolStateChange{.slot = slot_of(id),
                                            .type = to_proto(after.type),
                                            .function = function_number_of(id),
                                            .from = to_proto(from),
                                            .to = to_proto(after.state),
                                            .owner_vm = vm.value_or(after.owner.value_or(0))});
}

// ---- status ----------------------------------------------------------------

auto CommandRouter::inventory() const -> proto::Inventory {
    proto::Inventory inv;
    inv.last_command_seq = _last_seq;
    bool faulted = false;
    for (const auto& f : _pool->all()) {
        faulted = faulted || f.state == FunctionState::faulted;
        inv.functions.push_back({.slot = slot_of(f.id),
                                 .type = to_proto(f.type),
                                 .function = function_number_of(f.id),
                                 .state = to_proto(f.state),
                                 .owner_vm = f.owner.value_or(0)});
    }
    inv.health = faulted ? proto::Health::degraded : proto::Health::ok;
    for (const auto& [id, vm] : _vms) {
        inv.vms.push_back({.vm_id = id, .vcpus = vm.vcpus, .memory_mib = vm.memory_mib});
    }
    for (const auto& [id, volume] : _volumes) {
        inv.volumes.push_back(
            {.volume_id = id, .owner_vm = volume.owner, .size_gib = volume.size_gib});
    }
    for (const auto& [vni, version] : _networks) {
        inv.networks.push_back({.vni = vni, .map_version = version});
    }
    return inv;
}

}  // namespace ak::helm
