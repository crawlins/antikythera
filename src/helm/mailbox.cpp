// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/mailbox.hpp"

#include <algorithm>
#include <optional>
#include <utility>
#include <variant>

#include "common/wire.hpp"
#include "helm/device_pool.hpp"

namespace ak::helm::mailbox {

namespace {

// The wire's DeviceType and the pool's FunctionType are the same numbering.
static_assert(std::to_underlying(DeviceType::nic_vf) == std::to_underlying(FunctionType::nic_vf));
static_assert(std::to_underlying(DeviceType::blk_fn) == std::to_underlying(FunctionType::blk_fn));
static_assert(std::to_underlying(DeviceType::gpu_whole) ==
              std::to_underlying(FunctionType::gpu_whole));
static_assert(std::to_underlying(DeviceType::gpu_vf) == std::to_underlying(FunctionType::gpu_vf));

constexpr std::size_t create_vm_body_len = 16;
constexpr std::size_t destroy_vm_body_len = 9;
constexpr std::uint16_t max_vcpus = 1024;

constexpr std::size_t list_vms_body_len = 0;
constexpr std::size_t vm_status_body_len = 8;
constexpr std::size_t attach_device_body_len = 32;
constexpr std::size_t detach_device_body_len = 16;
constexpr std::size_t create_volume_body_len = 20;
constexpr std::size_t create_image_volume_body_len = create_volume_body_len + 4 + image_name_size;
constexpr std::size_t delete_volume_body_len = 8;
constexpr std::size_t attach_volume_body_len = 20;
constexpr std::size_t detach_volume_body_len = 24;
constexpr std::size_t rewrap_volume_body_len = 24;
constexpr std::size_t network_body_len = 4;
constexpr std::size_t vm_exited_body_len = 14;
constexpr std::size_t device_released_body_len = 14;
constexpr std::size_t host_fault_body_len = 12;
constexpr std::size_t scrub_done_body_len = 6;
constexpr std::uint8_t reserved_byte = 0;

constexpr auto known_type(std::uint16_t raw) noexcept -> bool {
    switch (static_cast<Type>(raw)) {
        case Type::create_vm:
        case Type::destroy_vm:
        case Type::list_vms:
        case Type::vm_status:
        case Type::attach_device:
        case Type::detach_device:
        case Type::create_volume:
        case Type::delete_volume:
        case Type::attach_volume:
        case Type::detach_volume:
        case Type::rewrap_volume:
        case Type::create_network:
        case Type::delete_network:
        case Type::gpu_vf_config:
        case Type::response:
        case Type::vm_exited:
        case Type::device_released:
        case Type::host_fault:
        case Type::scrub_done:
            return true;
    }
    return false;
}

// Commands must name their signing key; unsigned messages must not.
auto key_id_fits(Type type, KeyId key_id) noexcept -> bool {
    return is_command(type) ? key_id != no_key_id : key_id == no_key_id;
}

// Commands must name the server they are for; unsigned messages must not.
auto server_id_fits(Type type, ServerId server_id) noexcept -> bool {
    return is_command(type) ? server_id != no_server_id : server_id == no_server_id;
}

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

// ---- Field readers and validators ---------------------------------------
//
// Body decoders check body_len against the fixed size first, so every read
// below is in bounds; the dereferences cannot fail.

auto read_device(wire::Reader& r) noexcept -> std::optional<DeviceRef> {
    DeviceRef d;
    d.slot = *r.u8();
    const std::uint8_t type = *r.u8();
    d.function = *r.le16();
    switch (static_cast<DeviceType>(type)) {
        case DeviceType::nic_vf:
        case DeviceType::blk_fn:
        case DeviceType::gpu_whole:
        case DeviceType::gpu_vf:
            d.type = static_cast<DeviceType>(type);
            return d;
    }
    return std::nullopt;
}

auto write_device(wire::Writer& w, const DeviceRef& d) -> void {
    w.u8(d.slot);
    w.u8(std::to_underlying(d.type));
    w.le16(d.function);
}

constexpr auto valid_policy(std::uint8_t raw) noexcept -> bool {
    return raw == std::to_underlying(DetachPolicy::force) ||
           raw == std::to_underlying(DetachPolicy::destroy_vm);
}

constexpr auto valid_timeout(std::uint16_t t) noexcept -> bool {
    return t != 0 && t <= max_detach_timeout_s;
}

constexpr auto valid_vni(std::uint32_t vni) noexcept -> bool {
    return vni != 0 && vni <= max_vni;
}

// A guest NIC's MAC: unicast (I/G bit clear) and locally administered (U/L
// bit set), so it can never collide with a vendor-assigned address.
constexpr std::byte mac_multicast_bit{0x01};
constexpr std::byte mac_local_bit{0x02};

auto valid_nic_mac(const Mac& mac) noexcept -> bool {
    return (mac[0] & mac_multicast_bit) == std::byte{0} && (mac[0] & mac_local_bit) != std::byte{0};
}

constexpr auto is_gpu(DeviceType t) noexcept -> bool {
    return t == DeviceType::gpu_whole || t == DeviceType::gpu_vf;
}

constexpr auto valid_status(std::uint16_t raw) noexcept -> bool {
    return raw <= std::to_underlying(Status::wrong_server);
}

constexpr auto takes_payload(Type command) noexcept -> bool {
    return command == Type::list_vms || command == Type::vm_status;
}

auto invalid() noexcept -> std::unexpected<BodyError> {
    return std::unexpected(BodyError::invalid_field);
}

// Checks the type and exact length shared by every fixed-size body.
auto check_shape(const Message& msg, Type type, std::size_t len) noexcept
    -> std::expected<wire::Reader, BodyError> {
    if (msg.header.type != type) {
        return std::unexpected(BodyError::wrong_type);
    }
    if (msg.header.body_len != len) {
        return std::unexpected(BodyError::wrong_length);
    }
    return wire::Reader{msg.body_bytes()};
}

// ---- Per-type decoders ----------------------------------------------------

auto decode_list_vms(const Message& msg) noexcept -> std::expected<ListVms, BodyError> {
    return check_shape(msg, Type::list_vms, list_vms_body_len).transform([](auto&&) {
        return ListVms{};
    });
}

auto decode_vm_status(const Message& msg) noexcept -> std::expected<VmStatus, BodyError> {
    auto r = check_shape(msg, Type::vm_status, vm_status_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    VmStatus out{.vm_id = *r->le64()};
    if (out.vm_id == 0) {
        return invalid();
    }
    return out;
}

auto decode_attach_device(const Message& msg) noexcept -> std::expected<AttachDevice, BodyError> {
    auto r = check_shape(msg, Type::attach_device, attach_device_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    AttachDevice out;
    out.vm_id = *r->le64();
    const auto dev = read_device(*r);
    out.vni = *r->le32();
    out.nic_id = *r->le64();
    const auto mac = *r->bytes(out.mac.size());
    std::ranges::copy(mac, out.mac.begin());
    const std::uint16_t rsvd = *r->le16();
    if (out.vm_id == 0 || !dev || dev->type == DeviceType::blk_fn || rsvd != 0) {
        return invalid();
    }
    out.device = *dev;
    const bool nic_fields_ok = out.device.type == DeviceType::nic_vf
                                   ? valid_vni(out.vni) && out.nic_id != 0 && valid_nic_mac(out.mac)
                                   : out.vni == 0 && out.nic_id == 0 && all_zero(out.mac);
    if (!nic_fields_ok) {
        return invalid();
    }
    return out;
}

auto decode_detach_device(const Message& msg) noexcept -> std::expected<DetachDevice, BodyError> {
    auto r = check_shape(msg, Type::detach_device, detach_device_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    DetachDevice out;
    out.vm_id = *r->le64();
    const auto dev = read_device(*r);
    out.timeout_s = *r->le16();
    const std::uint8_t policy = *r->u8();
    const std::uint8_t rsvd = *r->u8();
    if (out.vm_id == 0 || !dev || dev->type == DeviceType::blk_fn ||
        !valid_timeout(out.timeout_s) || !valid_policy(policy) || rsvd != reserved_byte) {
        return invalid();
    }
    out.device = *dev;
    out.policy = static_cast<DetachPolicy>(policy);
    return out;
}

auto decode_create_volume(const Message& msg) noexcept -> std::expected<CreateVolume, BodyError> {
    // Two shapes: a disk volume, or one with an image source.
    const bool image = msg.header.type == Type::create_volume &&
                       msg.header.body_len == create_image_volume_body_len;
    auto r = check_shape(msg, Type::create_volume,
                         image ? create_image_volume_body_len : create_volume_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    CreateVolume out;
    out.volume_id = *r->le64();
    out.owner_vm = *r->le64();
    out.size_gib = *r->le32();
    if (out.volume_id == 0 || out.owner_vm == 0 || out.size_gib == 0 ||
        out.size_gib > max_volume_gib) {
        return invalid();
    }
    if (image) {
        out.image_store = *r->le16();
        const auto rsvd = *r->le16();
        const auto name = *r->bytes(image_name_size);
        std::ranges::copy(name, out.image_name.begin());
        if (out.image_store == 0 || rsvd != 0 || all_zero(out.image_name)) {
            return invalid();
        }
    }
    return out;
}

auto decode_delete_volume(const Message& msg) noexcept -> std::expected<DeleteVolume, BodyError> {
    auto r = check_shape(msg, Type::delete_volume, delete_volume_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    DeleteVolume out{.volume_id = *r->le64()};
    if (out.volume_id == 0) {
        return invalid();
    }
    return out;
}

auto decode_attach_volume(const Message& msg) noexcept -> std::expected<AttachVolume, BodyError> {
    auto r = check_shape(msg, Type::attach_volume, attach_volume_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    AttachVolume out;
    out.volume_id = *r->le64();
    out.vm_id = *r->le64();
    const auto dev = read_device(*r);
    if (out.volume_id == 0 || out.vm_id == 0 || !dev || dev->type != DeviceType::blk_fn) {
        return invalid();
    }
    out.device = *dev;
    return out;
}

auto decode_detach_volume(const Message& msg) noexcept -> std::expected<DetachVolume, BodyError> {
    auto r = check_shape(msg, Type::detach_volume, detach_volume_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    DetachVolume out;
    out.volume_id = *r->le64();
    out.vm_id = *r->le64();
    const auto dev = read_device(*r);
    out.timeout_s = *r->le16();
    const std::uint8_t policy = *r->u8();
    const std::uint8_t rsvd = *r->u8();
    if (out.volume_id == 0 || out.vm_id == 0 || !dev || dev->type != DeviceType::blk_fn ||
        !valid_timeout(out.timeout_s) || !valid_policy(policy) || rsvd != reserved_byte) {
        return invalid();
    }
    out.device = *dev;
    out.policy = static_cast<DetachPolicy>(policy);
    return out;
}

auto decode_rewrap_volume(const Message& msg) noexcept -> std::expected<RewrapVolume, BodyError> {
    auto r = check_shape(msg, Type::rewrap_volume, rewrap_volume_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    RewrapVolume out;
    out.volume_id = *r->le64();
    out.from_vm = *r->le64();
    out.to_vm = *r->le64();
    if (out.volume_id == 0 || out.from_vm == 0 || out.to_vm == 0 || out.from_vm == out.to_vm) {
        return invalid();
    }
    return out;
}

template<typename T>
auto decode_network(const Message& msg, Type type) noexcept -> std::expected<T, BodyError> {
    auto r = check_shape(msg, type, network_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    T out{.vni = *r->le32()};
    if (!valid_vni(out.vni)) {
        return invalid();
    }
    return out;
}

auto decode_response(const Message& msg) noexcept -> std::expected<Response, BodyError> {
    if (msg.header.type != Type::response) {
        return std::unexpected(BodyError::wrong_type);
    }
    if (msg.header.body_len < response_fixed_size) {
        return std::unexpected(BodyError::wrong_length);
    }
    wire::Reader r{msg.body_bytes()};
    Response out;
    out.in_reply_to = *r.le64();
    const std::uint16_t command = *r.le16();
    const std::uint16_t status = *r.le16();
    if (!known_type(command) || !is_command(static_cast<Type>(command)) || !valid_status(status)) {
        return invalid();
    }
    out.command = static_cast<Type>(command);
    out.status = static_cast<Status>(status);
    const auto payload = r.rest();
    if (!payload.empty() && (out.status != Status::ok || !takes_payload(out.command))) {
        return invalid();
    }
    // body_len <= max_body, so the payload fits and its length fits a u8.
    out.payload_len = static_cast<std::uint8_t>(payload.size());
    std::ranges::copy(payload, out.payload.begin());
    return out;
}

auto decode_vm_exited(const Message& msg) noexcept -> std::expected<VmExited, BodyError> {
    auto r = check_shape(msg, Type::vm_exited, vm_exited_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    VmExited out;
    out.vm_id = *r->le64();
    out.exit_status = *r->le32();
    const std::uint8_t reason = *r->u8();
    const std::uint8_t rsvd = *r->u8();
    const bool known_reason = reason >= std::to_underlying(ExitReason::guest_shutdown) &&
                              reason <= std::to_underlying(ExitReason::vmm_failure);
    if (out.vm_id == 0 || !known_reason || rsvd != reserved_byte) {
        return invalid();
    }
    out.reason = static_cast<ExitReason>(reason);
    return out;
}

auto decode_device_released(const Message& msg) noexcept
    -> std::expected<DeviceReleased, BodyError> {
    auto r = check_shape(msg, Type::device_released, device_released_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    DeviceReleased out;
    out.vm_id = *r->le64();
    const auto dev = read_device(*r);
    const std::uint8_t reset = *r->u8();
    const std::uint8_t rsvd = *r->u8();
    if (out.vm_id == 0 || !dev || reset > std::to_underlying(ResetResult::failed) ||
        rsvd != reserved_byte) {
        return invalid();
    }
    out.device = *dev;
    out.reset = static_cast<ResetResult>(reset);
    return out;
}

auto decode_host_fault(const Message& msg) noexcept -> std::expected<HostFault, BodyError> {
    auto r = check_shape(msg, Type::host_fault, host_fault_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    HostFault out;
    const std::uint16_t code = *r->le16();
    out.slot = *r->u8();
    const std::uint8_t rsvd = *r->u8();
    out.detail = *r->le64();
    const bool known_code = code >= std::to_underlying(FaultCode::iommu_fault) &&
                            code <= std::to_underlying(FaultCode::resources_exhausted);
    if (!known_code || rsvd != reserved_byte) {
        return invalid();
    }
    out.code = static_cast<FaultCode>(code);
    return out;
}

auto decode_scrub_done(const Message& msg) noexcept -> std::expected<ScrubDone, BodyError> {
    auto r = check_shape(msg, Type::scrub_done, scrub_done_body_len);
    if (!r) {
        return std::unexpected(r.error());
    }
    ScrubDone out;
    const auto dev = read_device(*r);
    const std::uint8_t result = *r->u8();
    const std::uint8_t rsvd = *r->u8();
    if (!dev || !is_gpu(dev->type) || result > std::to_underlying(ScrubResult::failed) ||
        rsvd != reserved_byte) {
        return invalid();
    }
    out.device = *dev;
    out.result = static_cast<ScrubResult>(result);
    return out;
}

// Widens expected<T> to expected<Body>.
template<typename T>
auto to_body(std::expected<T, BodyError> r) noexcept -> std::expected<Body, BodyError> {
    if (!r) {
        return std::unexpected(r.error());
    }
    return Body{std::move(*r)};
}

template<typename... F> struct Overloaded : F... {
    using F::operator()...;
};

}  // namespace

auto is_command(Type t) noexcept -> bool {
    return std::to_underlying(t) < std::to_underlying(Type::response);
}

auto to_string(DecodeError e) noexcept -> const char* {
    switch (e) {
        case DecodeError::bad_magic:
            return "bad_magic";
        case DecodeError::bad_version:
            return "bad_version";
        case DecodeError::unknown_type:
            return "unknown_type";
        case DecodeError::body_too_long:
            return "body_too_long";
        case DecodeError::reserved_not_zero:
            return "reserved_not_zero";
        case DecodeError::bad_key_id:
            return "bad_key_id";
        case DecodeError::bad_server_id:
            return "bad_server_id";
    }
    return "unknown";
}

auto to_string(BodyError e) noexcept -> const char* {
    switch (e) {
        case BodyError::wrong_type:
            return "wrong_type";
        case BodyError::wrong_length:
            return "wrong_length";
        case BodyError::invalid_field:
            return "invalid_field";
        case BodyError::reserved_type:
            return "reserved_type";
    }
    return "unknown";
}

auto decode(const Slot& slot) noexcept -> std::expected<Message, DecodeError> {
    wire::Reader r{slot};
    // The slot is a fixed 256 bytes, so none of these header reads can fail.
    Message msg;
    msg.header.magic = *r.le32();
    msg.header.version = *r.le16();
    const std::uint16_t raw_type = *r.le16();
    msg.header.seq = *r.le64();
    msg.header.body_len = *r.le16();
    msg.header.key_id = *r.le16();
    const auto reserved = *r.bytes(header_reserved_size);
    msg.header.server_id = *r.le64();

    if (msg.header.magic != magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (msg.header.version != protocol_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!known_type(raw_type)) {
        return std::unexpected(DecodeError::unknown_type);
    }
    msg.header.type = static_cast<Type>(raw_type);
    if (msg.header.body_len > max_body) {
        return std::unexpected(DecodeError::body_too_long);
    }
    if (!all_zero(reserved)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (!key_id_fits(msg.header.type, msg.header.key_id)) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (!server_id_fits(msg.header.type, msg.header.server_id)) {
        return std::unexpected(DecodeError::bad_server_id);
    }

    const auto body_region = std::span{slot}.subspan(header_size, max_body);
    // Bytes past body_len must be zero: no hidden data in the signed region.
    if (!all_zero(body_region.subspan(msg.header.body_len))) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    std::ranges::copy(body_region, msg.body.begin());
    std::ranges::copy(std::span{slot}.subspan(signature_offset, signature_size),
                      msg.signature.begin());
    return msg;
}

auto encode(const Header& header, std::span<const std::byte> body,
            std::span<const std::byte, signature_size> signature)
    -> std::expected<Slot, DecodeError> {
    if (body.size() > max_body || header.body_len != body.size()) {
        return std::unexpected(DecodeError::body_too_long);
    }
    if (!known_type(std::to_underlying(header.type))) {
        return std::unexpected(DecodeError::unknown_type);
    }
    if (!key_id_fits(header.type, header.key_id)) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (!server_id_fits(header.type, header.server_id)) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    Slot slot{};
    wire::SpanWriter w{slot};
    // Fixed-size slot: these writes cannot overflow.
    (void)w.write(header.magic, wire::Order::little);
    (void)w.write(header.version, wire::Order::little);
    (void)w.write(std::to_underlying(header.type), wire::Order::little);
    (void)w.write(header.seq, wire::Order::little);
    (void)w.write(header.body_len, wire::Order::little);
    (void)w.write(header.key_id, wire::Order::little);
    (void)w.write(std::uint32_t{0}, wire::Order::little);  // reserved
    (void)w.write(header.server_id, wire::Order::little);
    std::ranges::copy(body, slot.begin() + header_size);
    std::ranges::copy(signature, slot.begin() + signature_offset);
    return slot;
}

auto decode_create_vm(const Message& msg) noexcept -> std::expected<CreateVm, BodyError> {
    if (msg.header.type != Type::create_vm) {
        return std::unexpected(BodyError::wrong_type);
    }
    if (msg.header.body_len != create_vm_body_len) {
        return std::unexpected(BodyError::wrong_length);
    }
    // body: vm_id u64 | vcpus u16 | memory_mib u32 | boot_mode u8 | rsvd u8
    wire::Reader r{msg.body_bytes()};
    CreateVm out;
    out.vm_id = *r.le64();
    out.vcpus = *r.le16();
    out.memory_mib = *r.le32();
    const std::uint8_t boot = *r.u8();
    const std::uint8_t rsvd = *r.u8();
    if (out.vm_id == 0 || out.vcpus == 0 || out.vcpus > max_vcpus || out.memory_mib == 0 ||
        boot != std::to_underlying(BootMode::volume) || rsvd != 0) {
        return std::unexpected(BodyError::invalid_field);
    }
    out.boot_mode = BootMode::volume;
    return out;
}

auto decode_destroy_vm(const Message& msg) noexcept -> std::expected<DestroyVm, BodyError> {
    if (msg.header.type != Type::destroy_vm) {
        return std::unexpected(BodyError::wrong_type);
    }
    if (msg.header.body_len != destroy_vm_body_len) {
        return std::unexpected(BodyError::wrong_length);
    }
    // body: vm_id u64 | flags u8 (bit 0 = persist volumes; others must be 0)
    wire::Reader r{msg.body_bytes()};
    DestroyVm out;
    out.vm_id = *r.le64();
    const std::uint8_t flags = *r.u8();
    if (out.vm_id == 0 || (flags & static_cast<std::uint8_t>(~destroy_flags_known)) != 0) {
        return std::unexpected(BodyError::invalid_field);
    }
    out.persist_volumes = (flags & destroy_flag_persist_volumes) != 0;
    return out;
}

auto decode_body(const Message& msg) noexcept -> std::expected<Body, BodyError> {
    switch (msg.header.type) {
        case Type::create_vm:
            return to_body(decode_create_vm(msg));
        case Type::destroy_vm:
            return to_body(decode_destroy_vm(msg));
        case Type::list_vms:
            return to_body(decode_list_vms(msg));
        case Type::vm_status:
            return to_body(decode_vm_status(msg));
        case Type::attach_device:
            return to_body(decode_attach_device(msg));
        case Type::detach_device:
            return to_body(decode_detach_device(msg));
        case Type::create_volume:
            return to_body(decode_create_volume(msg));
        case Type::delete_volume:
            return to_body(decode_delete_volume(msg));
        case Type::attach_volume:
            return to_body(decode_attach_volume(msg));
        case Type::detach_volume:
            return to_body(decode_detach_volume(msg));
        case Type::rewrap_volume:
            return to_body(decode_rewrap_volume(msg));
        case Type::create_network:
            return to_body(decode_network<CreateNetwork>(msg, Type::create_network));
        case Type::delete_network:
            return to_body(decode_network<DeleteNetwork>(msg, Type::delete_network));
        case Type::gpu_vf_config:
            return std::unexpected(BodyError::reserved_type);
        case Type::response:
            return to_body(decode_response(msg));
        case Type::vm_exited:
            return to_body(decode_vm_exited(msg));
        case Type::device_released:
            return to_body(decode_device_released(msg));
        case Type::host_fault:
            return to_body(decode_host_fault(msg));
        case Type::scrub_done:
            return to_body(decode_scrub_done(msg));
    }
    // decode() admits only known types, but a hand-built Message may not.
    return std::unexpected(BodyError::wrong_type);
}

auto type_of(const Body& body) noexcept -> Type {
    return std::visit(Overloaded{
                          [](const ListVms&) { return Type::list_vms; },
                          [](const VmStatus&) { return Type::vm_status; },
                          [](const CreateVm&) { return Type::create_vm; },
                          [](const DestroyVm&) { return Type::destroy_vm; },
                          [](const AttachDevice&) { return Type::attach_device; },
                          [](const DetachDevice&) { return Type::detach_device; },
                          [](const CreateVolume&) { return Type::create_volume; },
                          [](const DeleteVolume&) { return Type::delete_volume; },
                          [](const AttachVolume&) { return Type::attach_volume; },
                          [](const DetachVolume&) { return Type::detach_volume; },
                          [](const RewrapVolume&) { return Type::rewrap_volume; },
                          [](const CreateNetwork&) { return Type::create_network; },
                          [](const DeleteNetwork&) { return Type::delete_network; },
                          [](const Response&) { return Type::response; },
                          [](const VmExited&) { return Type::vm_exited; },
                          [](const DeviceReleased&) { return Type::device_released; },
                          [](const HostFault&) { return Type::host_fault; },
                          [](const ScrubDone&) { return Type::scrub_done; },
                      },
                      body);
}

auto encode_body(const Body& body) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    wire::Writer w{out};
    std::visit(Overloaded{
                   [](const ListVms&) {},
                   [&](const VmStatus& b) { w.le64(b.vm_id); },
                   [&](const CreateVm& b) {
                       w.le64(b.vm_id);
                       w.le16(b.vcpus);
                       w.le32(b.memory_mib);
                       w.u8(std::to_underlying(b.boot_mode));
                       w.u8(reserved_byte);
                   },
                   [&](const DestroyVm& b) {
                       w.le64(b.vm_id);
                       w.u8(b.persist_volumes ? destroy_flag_persist_volumes : std::uint8_t{0});
                   },
                   [&](const AttachDevice& b) {
                       w.le64(b.vm_id);
                       write_device(w, b.device);
                       w.le32(b.vni);
                       w.le64(b.nic_id);
                       w.bytes(b.mac);
                       w.le16(0);
                   },
                   [&](const DetachDevice& b) {
                       w.le64(b.vm_id);
                       write_device(w, b.device);
                       w.le16(b.timeout_s);
                       w.u8(std::to_underlying(b.policy));
                       w.u8(reserved_byte);
                   },
                   [&](const CreateVolume& b) {
                       w.le64(b.volume_id);
                       w.le64(b.owner_vm);
                       w.le32(b.size_gib);
                       if (b.image_store != 0) {
                           w.le16(b.image_store);
                           w.le16(0);
                           w.bytes(b.image_name);
                       }
                   },
                   [&](const DeleteVolume& b) { w.le64(b.volume_id); },
                   [&](const AttachVolume& b) {
                       w.le64(b.volume_id);
                       w.le64(b.vm_id);
                       write_device(w, b.device);
                   },
                   [&](const DetachVolume& b) {
                       w.le64(b.volume_id);
                       w.le64(b.vm_id);
                       write_device(w, b.device);
                       w.le16(b.timeout_s);
                       w.u8(std::to_underlying(b.policy));
                       w.u8(reserved_byte);
                   },
                   [&](const RewrapVolume& b) {
                       w.le64(b.volume_id);
                       w.le64(b.from_vm);
                       w.le64(b.to_vm);
                   },
                   [&](const CreateNetwork& b) { w.le32(b.vni); },
                   [&](const DeleteNetwork& b) { w.le32(b.vni); },
                   [&](const Response& b) {
                       w.le64(b.in_reply_to);
                       w.le16(std::to_underlying(b.command));
                       w.le16(std::to_underlying(b.status));
                       w.bytes(std::span{b.payload}.first(
                           std::min<std::size_t>(b.payload_len, max_response_payload)));
                   },
                   [&](const VmExited& b) {
                       w.le64(b.vm_id);
                       w.le32(b.exit_status);
                       w.u8(std::to_underlying(b.reason));
                       w.u8(reserved_byte);
                   },
                   [&](const DeviceReleased& b) {
                       w.le64(b.vm_id);
                       write_device(w, b.device);
                       w.u8(std::to_underlying(b.reset));
                       w.u8(reserved_byte);
                   },
                   [&](const HostFault& b) {
                       w.le16(std::to_underlying(b.code));
                       w.u8(b.slot);
                       w.u8(reserved_byte);
                       w.le64(b.detail);
                   },
                   [&](const ScrubDone& b) {
                       write_device(w, b.device);
                       w.u8(std::to_underlying(b.result));
                       w.u8(reserved_byte);
                   },
               },
               body);
    return out;
}

}  // namespace ak::helm::mailbox
