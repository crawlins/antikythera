// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Control-plane mailbox: the only channel between the control-plane role
// (helm) and the host agent (hull). It is a register file in the control
// device's BAR0; the agent maps it through VFIO and never gives the device
// any DMA mapping, so every message lives in device memory and is copied
// out once with MMIO before it is parsed.
//
// All multi-byte fields are little-endian (PCIe native order).
//
// BAR0 layout:
//   0x000  MAGIC        RO  'AKMB'
//   0x004  VERSION      RO  protocol version
//   0x008  CMD_DOORBELL RO  device->host: incremented when CMD_SLOT holds a new command
//   0x00C  RSP_DOORBELL WO  host->device: response written to RSP_SLOT
//   0x010  EVT_DOORBELL WO  host->device: event written to EVT_SLOT
//   0x100  CMD_SLOT     256 bytes, device writes, host reads
//   0x200  RSP_SLOT     256 bytes, host writes, device reads
//   0x300  EVT_SLOT     256 bytes, host writes, device reads
//
// Slot layout (256 bytes):
//   0x00  header (32 bytes):
//           0x00 magic u32 | 0x04 version u16 | 0x06 type u16 | 0x08 seq u64
//           0x10 body_len u16 | 0x12 key_id u16 | 0x14 reserved (4 bytes, zero)
//           0x18 server_id u64
//   0x20  body   (up to 160 bytes; body_len says how much is meaningful)
//   0xC0  Ed25519 signature (64 bytes) over bytes [0x00, 0xC0) -- commands only

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <variant>
#include <vector>

namespace ak::helm::mailbox {

inline constexpr std::uint32_t magic = 0x424D'4B41;  // "AKMB" read as little-endian bytes
// Version 2 assigned key_id (two of version 1's six reserved header bytes).
// Version 3 grew the header to 32 bytes for server_id, so a signed command
// names the one server it is for, and gave ATTACH_DEVICE the NIC's VPC,
// NIC ID and MAC. Nothing speaks older versions, so decode accepts 3 only.
inline constexpr std::uint16_t protocol_version = 3;

namespace reg {
inline constexpr std::size_t magic = 0x000;
inline constexpr std::size_t version = 0x004;
inline constexpr std::size_t cmd_doorbell = 0x008;
inline constexpr std::size_t rsp_doorbell = 0x00C;
inline constexpr std::size_t evt_doorbell = 0x010;
inline constexpr std::size_t cmd_slot = 0x100;
inline constexpr std::size_t rsp_slot = 0x200;
inline constexpr std::size_t evt_slot = 0x300;
inline constexpr std::size_t bar0_size = 0x1000;
}  // namespace reg

inline constexpr std::size_t slot_size = 256;
inline constexpr std::size_t header_size = 32;
inline constexpr std::size_t signature_size = 64;
inline constexpr std::size_t signature_offset = slot_size - signature_size;  // 0xC0
inline constexpr std::size_t max_body = signature_offset - header_size;      // 160
inline constexpr std::size_t header_key_id_offset = 0x12;
inline constexpr std::size_t header_reserved_offset = 0x14;
inline constexpr std::size_t header_reserved_size = 4;
inline constexpr std::size_t header_server_id_offset = 0x18;

// Which controller signing key signed a command
// (.kiro/specs/controller-interface/ Requirement 1.3). It sits inside the
// signed bytes [0x00, 0xC0), so hull picks the verification key from data
// the signature covers, never from the unsigned envelope around the slot.
// Commands carry a non-zero key ID; responses and events are not signed and
// carry no_key_id.
using KeyId = std::uint16_t;
inline constexpr KeyId no_key_id = 0;

// The server a command is for (.kiro/specs/controller-interface/ Requirement
// 1.2, design "Envelope"). Like key_id it lies inside the signed bytes, so a
// command signed for one server is refused by every other server's hull
// before any other check, whatever their sequence floors. Commands carry a
// non-zero server ID; responses and events carry no_server_id.
using ServerId = std::uint64_t;
inline constexpr ServerId no_server_id = 0;

using Slot = std::array<std::byte, slot_size>;

// Message types. Values are part of the wire protocol: never renumber.
enum class Type : std::uint16_t {
    // Commands (operator -> control plane -> host agent).
    create_vm = 0x0001,
    destroy_vm = 0x0002,
    list_vms = 0x0003,
    vm_status = 0x0004,
    attach_device = 0x0010,  // NIC VF, storage function, GPU / GPU VF
    detach_device = 0x0011,
    create_volume = 0x0020,
    delete_volume = 0x0021,
    attach_volume = 0x0022,
    detach_volume = 0x0023,
    rewrap_volume = 0x0024,
    create_network = 0x0030,  // VPC
    delete_network = 0x0031,
    gpu_vf_config = 0x0040,  // reserved: GPU support is designed, not yet built

    // Responses (host agent -> control plane).
    response = 0x0100,

    // Events (host agent -> control plane).
    vm_exited = 0x0200,
    device_released = 0x0201,  // slot/function reset done; control plane wipes or scrubs next
    host_fault = 0x0202,
    scrub_done = 0x0203,  // reserved for GPU scrub
};

[[nodiscard]] auto is_command(Type t) noexcept -> bool;

struct Header {
    std::uint32_t magic{mailbox::magic};
    std::uint16_t version{protocol_version};
    Type type{Type::response};
    std::uint64_t seq{0};
    std::uint16_t body_len{0};
    KeyId key_id{no_key_id};
    ServerId server_id{no_server_id};
};

// A message copied out of a slot. Owns its bytes, so it stays valid after
// the device overwrites the slot.
struct Message {
    Header header;
    std::array<std::byte, max_body> body{};
    std::array<std::byte, signature_size> signature{};

    [[nodiscard]] auto body_bytes() const noexcept -> std::span<const std::byte> {
        return std::span{body}.first(header.body_len);
    }
};

enum class DecodeError : std::uint8_t {
    bad_magic,
    bad_version,
    unknown_type,
    body_too_long,
    reserved_not_zero,  // reserved header bytes or bytes past body_len are non-zero
    bad_key_id,         // a command with no_key_id, or a response/event with a key ID
    bad_server_id,      // a command with no_server_id, or a response/event with one
};

[[nodiscard]] auto to_string(DecodeError e) noexcept -> const char*;

// Strict decode of one slot. Rejects anything not exactly well-formed;
// does not check signatures or sequence numbers (the agent does both).
[[nodiscard]] auto decode(const Slot& slot) noexcept -> std::expected<Message, DecodeError>;

// Encodes a message into a slot, zero-filling everything unused.
[[nodiscard]] auto encode(const Header& header, std::span<const std::byte> body,
                          std::span<const std::byte, signature_size> signature)
    -> std::expected<Slot, DecodeError>;

// ---- Command bodies -------------------------------------------------------

enum class BootMode : std::uint8_t {
    volume = 1,  // boot from an attached (endpoint-provided) volume via guest firmware
};

struct CreateVm {
    std::uint64_t vm_id{0};
    std::uint16_t vcpus{0};
    std::uint32_t memory_mib{0};
    BootMode boot_mode{BootMode::volume};
    friend auto operator==(const CreateVm&, const CreateVm&) -> bool = default;
};

inline constexpr std::uint8_t destroy_flag_persist_volumes = 0x01;
inline constexpr std::uint8_t destroy_flags_known = destroy_flag_persist_volumes;

struct DestroyVm {
    std::uint64_t vm_id{0};
    bool persist_volumes{false};
    friend auto operator==(const DestroyVm&, const DestroyVm&) -> bool = default;
};

enum class BodyError : std::uint8_t {
    wrong_type,
    wrong_length,
    invalid_field,
    reserved_type,  // the type is reserved in the protocol and has no body yet
};

[[nodiscard]] auto to_string(BodyError e) noexcept -> const char*;

[[nodiscard]] auto decode_create_vm(const Message& msg) noexcept
    -> std::expected<CreateVm, BodyError>;
[[nodiscard]] auto decode_destroy_vm(const Message& msg) noexcept
    -> std::expected<DestroyVm, BodyError>;

// Every other body. Layouts are listed field by field; all integers are
// little-endian and every reserved byte must be zero. Identifiers (VM,
// volume, NIC) are controller-assigned and never zero.

// A PCIe function on the backplane: which slot, which function in it, and
// what kind of function the command expects it to be. hull checks all three
// against its boot inventory (hull-host-agent Requirement 5.4).
//   slot u8 | device_type u8 | function u16  (4 bytes)
enum class DeviceType : std::uint8_t {
    nic_vf = 1,
    blk_fn = 2,
    gpu_whole = 3,  // reserved: GPU support is designed, not yet built
    gpu_vf = 4,     // reserved
};

struct DeviceRef {
    std::uint8_t slot{0};
    DeviceType type{DeviceType::nic_vf};
    std::uint16_t function{0};

    friend auto operator==(const DeviceRef&, const DeviceRef&) -> bool = default;
};

// What hull does when the guest has not ejected a function by the timeout
// (hull-host-agent Requirement 7.2).
enum class DetachPolicy : std::uint8_t {
    force = 1,       // hot-unplug anyway
    destroy_vm = 2,  // destroy the whole VM
};

inline constexpr std::uint16_t max_detach_timeout_s = 600;
inline constexpr std::uint32_t max_volume_gib = 65536;  // 64 TiB
inline constexpr std::uint32_t max_vni = 0xFF'FFFF;     // VNIs are 24 bits

// LIST_VMS: empty body.
struct ListVms {
    friend auto operator==(const ListVms&, const ListVms&) -> bool = default;
};

// VM_STATUS: vm_id u64  (8 bytes)
struct VmStatus {
    std::uint64_t vm_id{0};
    friend auto operator==(const VmStatus&, const VmStatus&) -> bool = default;
};

// ATTACH_DEVICE: vm_id u64 | device (4) | vni u32 | nic_id u64 | mac [6] |
// rsvd [2]  (32 bytes)
// Storage functions are attached only with ATTACH_VOLUME, which is what
// makes helm deliver the volume key, so device.type must not be blk_fn.
// For a NIC VF the controller names the VPC (1 <= vni <= 0xFFFFFF), the
// region-unique NIC ID (non-zero) and the MAC (locally administered
// unicast); helm hands them to oar-net, the only place they are set
// (helm-control-plane Requirement 8.1). For a GPU they must all be zero.
using Mac = std::array<std::byte, 6>;

struct AttachDevice {
    std::uint64_t vm_id{0};
    DeviceRef device;
    std::uint32_t vni{0};
    std::uint64_t nic_id{0};
    Mac mac{};
    friend auto operator==(const AttachDevice&, const AttachDevice&) -> bool = default;
};

// DETACH_DEVICE: vm_id u64 | device (4) | timeout_s u16 | policy u8 | rsvd u8
// (16 bytes). device.type must not be blk_fn; 1 <= timeout_s <= 600.
struct DetachDevice {
    std::uint64_t vm_id{0};
    DeviceRef device;
    std::uint16_t timeout_s{0};
    DetachPolicy policy{DetachPolicy::force};
    friend auto operator==(const DetachDevice&, const DetachDevice&) -> bool = default;
};

// CREATE_VOLUME: volume_id u64 | owner_vm u64 | size_gib u32  (20 bytes)
// 1 <= size_gib <= 65536.
// An image volume (oar-blk Requirement 8) adds its image source:
//   ... | image_store u16 | reserved u16 | image_name [32]  (56 bytes)
// image_store (non-zero) names an object store the storage role is
// configured with; image_name is the image's name, the SHA-256 of its
// manifest (never all zero). The volume is that image under a throwaway
// overlay: helm creates no volume key for it, and draws a fresh ephemeral
// key at each ATTACH_VOLUME instead.
inline constexpr std::size_t image_name_size = 32;
using ImageName = std::array<std::byte, image_name_size>;

struct CreateVolume {
    std::uint64_t volume_id{0};
    std::uint64_t owner_vm{0};
    std::uint32_t size_gib{0};
    std::uint16_t image_store{0};  // non-zero: an image volume
    ImageName image_name{};        // set exactly when image_store is
    friend auto operator==(const CreateVolume&, const CreateVolume&) -> bool = default;
};

// DELETE_VOLUME: volume_id u64  (8 bytes)
struct DeleteVolume {
    std::uint64_t volume_id{0};
    friend auto operator==(const DeleteVolume&, const DeleteVolume&) -> bool = default;
};

// ATTACH_VOLUME: volume_id u64 | vm_id u64 | device (4)  (20 bytes)
// device.type must be blk_fn.
struct AttachVolume {
    std::uint64_t volume_id{0};
    std::uint64_t vm_id{0};
    DeviceRef device;
    friend auto operator==(const AttachVolume&, const AttachVolume&) -> bool = default;
};

// DETACH_VOLUME: volume_id u64 | vm_id u64 | device (4) | timeout_s u16 |
// policy u8 | rsvd u8  (24 bytes). device.type must be blk_fn.
struct DetachVolume {
    std::uint64_t volume_id{0};
    std::uint64_t vm_id{0};
    DeviceRef device;
    std::uint16_t timeout_s{0};
    DetachPolicy policy{DetachPolicy::force};
    friend auto operator==(const DetachVolume&, const DetachVolume&) -> bool = default;
};

// REWRAP_VOLUME: volume_id u64 | from_vm u64 | to_vm u64  (24 bytes)
// Names the current owner as well as the new one, so a stale or reordered
// command cannot move a volume it no longer describes. from_vm != to_vm.
struct RewrapVolume {
    std::uint64_t volume_id{0};
    std::uint64_t from_vm{0};
    std::uint64_t to_vm{0};
    friend auto operator==(const RewrapVolume&, const RewrapVolume&) -> bool = default;
};

// CREATE_NETWORK / DELETE_NETWORK: vni u32  (4 bytes), 1 <= vni <= 0xFFFFFF.
struct CreateNetwork {
    std::uint32_t vni{0};
    friend auto operator==(const CreateNetwork&, const CreateNetwork&) -> bool = default;
};

struct DeleteNetwork {
    std::uint32_t vni{0};
    friend auto operator==(const DeleteNetwork&, const DeleteNetwork&) -> bool = default;
};

// GPU_VF_CONFIG has no body yet: decoding it fails with reserved_type.

// ---- Response body --------------------------------------------------------

// Values are part of the wire protocol: never renumber.
enum class Status : std::uint16_t {
    ok = 0,
    accepted = 1,  // long operation started; completion is reported by event
    bad_signature = 2,
    stale_sequence = 3,
    malformed = 4,
    unknown_vm = 5,
    unknown_device = 6,
    unknown_volume = 7,
    insufficient_resources = 8,
    conflict = 9,  // e.g. the device is already assigned
    timed_out = 10,
    internal_error = 11,
    unsupported = 12,
    wrong_server = 13,  // the command names another server (protocol v3 server_id)
};

inline constexpr std::size_t response_fixed_size = 12;
inline constexpr std::size_t max_response_payload = max_body - response_fixed_size;

// RESPONSE: in_reply_to u64 | command u16 | status u16 | payload
// in_reply_to is the command's sequence number and command its type. A
// payload is allowed only on an `ok` reply to LIST_VMS or VM_STATUS; its
// format belongs to those commands and is decoded by their callers.
struct Response {
    std::uint64_t in_reply_to{0};
    Type command{Type::list_vms};
    Status status{Status::ok};
    std::uint8_t payload_len{0};
    std::array<std::byte, max_response_payload> payload{};

    [[nodiscard]] auto payload_bytes() const noexcept -> std::span<const std::byte> {
        return std::span{payload}.first(payload_len);
    }
    friend auto operator==(const Response&, const Response&) -> bool = default;
};

// ---- Event bodies ---------------------------------------------------------

enum class ExitReason : std::uint8_t {
    guest_shutdown = 1,  // the guest powered off
    guest_fault = 2,     // triple fault, panic notifier, watchdog
    vmm_failure = 3,     // the VMM process died or was killed
};

// VM_EXITED: vm_id u64 | exit_status u32 | reason u8 | rsvd u8  (14 bytes)
// Sent for an exit hull did not cause (hull-host-agent Requirement 6.4).
struct VmExited {
    std::uint64_t vm_id{0};
    std::uint32_t exit_status{0};
    ExitReason reason{ExitReason::guest_shutdown};
    friend auto operator==(const VmExited&, const VmExited&) -> bool = default;
};

enum class ResetResult : std::uint8_t {
    ok = 0,
    failed = 1,  // helm moves the function to faulted (Requirement 3.4)
};

// DEVICE_RELEASED: vm_id u64 | device (4) | reset u8 | rsvd u8  (14 bytes)
// vm_id is the VM that held the function.
struct DeviceReleased {
    std::uint64_t vm_id{0};
    DeviceRef device;
    ResetResult reset{ResetResult::ok};
    friend auto operator==(const DeviceReleased&, const DeviceReleased&) -> bool = default;
};

enum class FaultCode : std::uint16_t {
    iommu_fault = 1,
    machine_check = 2,
    agent_restarted = 3,
    device_lost = 4,  // a function vanished or stopped responding
    resources_exhausted = 5,
};

inline constexpr std::uint8_t no_slot = 0xFF;

// HOST_FAULT: code u16 | slot u8 | rsvd u8 | detail u64  (12 bytes)
// slot is the backplane slot involved, or 0xFF for none; detail is
// fault-specific (e.g. the faulting IOVA) and opaque to the codec.
struct HostFault {
    FaultCode code{FaultCode::iommu_fault};
    std::uint8_t slot{no_slot};
    std::uint64_t detail{0};
    friend auto operator==(const HostFault&, const HostFault&) -> bool = default;
};

enum class ScrubResult : std::uint8_t {
    ok = 0,
    failed = 1,
};

// SCRUB_DONE (reserved for GPU scrub): device (4) | result u8 | rsvd u8
// (6 bytes). device.type must be gpu_whole or gpu_vf.
struct ScrubDone {
    DeviceRef device;
    ScrubResult result{ScrubResult::ok};
    friend auto operator==(const ScrubDone&, const ScrubDone&) -> bool = default;
};

// ---- Any body -------------------------------------------------------------

using Body =
    std::variant<ListVms, VmStatus, CreateVm, DestroyVm, AttachDevice, DetachDevice, CreateVolume,
                 DeleteVolume, AttachVolume, DetachVolume, RewrapVolume, CreateNetwork,
                 DeleteNetwork, Response, VmExited, DeviceReleased, HostFault, ScrubDone>;

// Decodes and validates the body of any message according to its type.
[[nodiscard]] auto decode_body(const Message& msg) noexcept -> std::expected<Body, BodyError>;

// The message type a body travels under.
[[nodiscard]] auto type_of(const Body& body) noexcept -> Type;

// Encodes a body to its wire bytes. Does not validate: a body that decode_body
// would reject encodes to bytes that decode_body rejects. For every body that
// decode_body accepts, encode_body(*decode_body(msg)) == msg.body_bytes().
[[nodiscard]] auto encode_body(const Body& body) -> std::vector<std::byte>;

}  // namespace ak::helm::mailbox
