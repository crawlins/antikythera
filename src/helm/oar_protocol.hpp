// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Message bodies of the helm <-> oar sideband protocol (OarLink,
// .kiro/specs/helm-control-plane/ Requirements 5 and 7, design "OarLink").
//
// Each operation is one ak vendor-defined MCTP message (helm/mctp.hpp,
// VendorType) sent by helm as a request and answered by the data-plane role
// with a response of the same VendorType and the response flag set. This
// header defines only the bodies, which follow the 7-byte vendor header.
// Integers are little-endian, like the mailbox and src/proto/.
//
// Requests (helm -> oar):
//
//   function_inventory  (empty)
//   prepare_function    0  fn u16 | 2  type u8 | 3  reserved u8 | 4  reserved u32
//                       8  vm_id u64 | 16 per-type config:
//                         nic_vf: nic_id u64 | vni u32 | mac [6] | reserved u16  (20 bytes)
//                         blk_fn: volume_id u64                                  (8 bytes)
//                         gpu_whole, gpu_vf: nothing
//   clean_function      0  fn u16 | 2  action u8 (CleaningAction) | 3  reserved u8
//   deliver_key         0  fn u16 | 2  reserved u16 | 4  reserved u32 | 8  volume_id u64
//                       16 key [64] (AES-256-XTS volume key, oar-blk Requirement 2)
//   drop_key            0  fn u16 | 2  reserved u16 | 4  reserved u32 | 8  volume_id u64
//   map_update          0  total u32 | 4  offset u32 | 8  chunk (1..max_map_chunk bytes)
//   health              (empty)
//   group_policy        0  frame [group_policy_frame_size] (proto::GroupPolicy, signed)
//   group_usage         0  cursor u16 | 2  reserved u16
//   create_volume       0  volume_id u64 | 8  owner_vm u64 | 16 capacity_sectors u64
//                       24 block_size u32 | 28 key_len u16 | 30 image_store u16
//                       32 image_name [32], only when image_store != 0
//                       wrapped_key [key_len]
//   delete_volume       0  volume_id u64
//   rewrap_volume       0  volume_id u64 | 8  owner_vm u64 | 16 key_len u16
//                       18 reserved u16 | 20 reserved u32 | 24 wrapped_key [key_len]
//   set_tunnel_key      0  private_key [32]
//   set_tunnel_peer     0  vtep [16] | 16 public_key [32] | 48 psk [32]
//   remove_tunnel_peer  0  vtep [16]
//
// The tunnel requests deliver the network role's WireGuard keys (oar-net
// Requirement 5.2): its own static X25519 private key, and for each peer
// VTEP that peer's public key and the pre-shared key for the pair (all
// zero for none, as in WireGuard). set_tunnel_peer adds the peer or
// replaces its keys. Private and public keys and VTEP addresses are never
// all zero. Only the network role implements them. The bodies carry
// secrets, so both ends wipe every buffer that held one, as for
// deliver_key.
//
// The volume requests are the storage role's half of CREATE_VOLUME,
// DELETE_VOLUME and REWRAP_VOLUME (oar-blk Requirement 3): the role keeps
// the wrapped volume key with the volume's metadata on the media and
// releases the space on delete. The wrapped key is helm's KeyStore blob,
// opaque to the role (helm authenticates it on unwrap); key_len is 1 to
// max_wrapped_volume_key. capacity_sectors counts 512-byte sectors, is
// non-zero and a whole number of logical blocks; block_size is 512 or 4096.
// A non-zero image_store makes it an image volume (oar-blk Requirement 8,
// task 13): the image named image_name (the SHA-256 of its manifest, never
// all zero) in the object store the role knows by that ID, under a
// throwaway overlay. Such a volume needs no volume key; key_len is 0 for a
// plain image, or carries the wrapped image key of an encrypted one. Its
// attachment key is the ephemeral one helm delivers with deliver_key.
//
// map_update forwards one controller MapUpdate frame (src/proto/map_update.hpp)
// unmodified, signature included, so the role can check it itself. A full
// frame (up to 131 KiB) is larger than an MCTP message may be here
// (mctp::max_message_size), so it travels as consecutive chunks: offset 0
// starts a transfer, each later chunk continues exactly where the last one
// ended, and the chunk that reaches `total` completes it. Every chunk is
// acknowledged; the last acknowledgement carries the result of applying it.
//
// group_policy forwards one controller GroupPolicy frame
// (src/proto/group_policy.hpp) unmodified, like map_update; it fits one
// message. group_usage reads the role's per-NIC group meters (oar-net
// Requirement 10.6) a page at a time: cursor 0 takes a new snapshot,
// later cursors page through it. A snapshot's final readings of detached
// NICs are carried into the next snapshot until a read reaches its last
// page, so an interrupted read loses nothing (UsagePager).
//
// Responses (oar -> helm) start with a 2-byte head:
//
//   0  status u8 (Status) | 1  reserved u8
//
// A response with any status other than ok ends there. An ok response to
// function_inventory or health carries a body after the head:
//
//   function_inventory  2  role u8 (Role) | 3  reserved u8 | 4  count u16
//                       6  vtep [16] (IPv6; the role's VTEP for net, zero otherwise)
//                       22 count x { fn u16 | type u8 (FunctionType) | reserved u8 }
//   health              2  state u8 (HealthState) | 3  reserved u8 | 4  fault_code u16
//                       6  uptime_seconds u32
//   group_usage         2  total u16 | 4  count u16 | 6  reserved u32
//                       10 count x 96 (the proto group_usage report entry, slot 0):
//                          nic_id u64 | vni u32 | flags u8 | reserved [3] | attachment u64
//                          frames, bytes, replicas_remote, replica_bytes_remote,
//                          replicas_local, replica_bytes_local, drop_policy,
//                          drop_rate, drop_fanout: u64 each
//                       entries [cursor, cursor + count) of the snapshot, which
//                       is in strictly increasing (nic_id, attachment) order
//
// Every decoder here is strict (exact length, zero reserved bytes, known
// enum values, non-zero identifiers) and every encoder enforces the same
// rules, so neither side can emit a body the other would refuse. The
// sideband is unauthenticated in the first release (Requirement 5.3), so
// helm parses responses with the same suspicion as the oar parses requests.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include "helm/device_pool.hpp"
#include "helm/mctp.hpp"
#include "helm/scoped_key.hpp"
#include "helm/secure_element.hpp"

namespace ak::helm::oar {

// A function's number within its slot (helm-control-plane design, data
// models: FunctionId { slot, fn }).
using FunctionNumber = std::uint16_t;
using NicId = std::uint64_t;

inline constexpr std::size_t mac_size = 6;
inline constexpr std::size_t vtep_size = 16;
using Mac = std::array<std::byte, mac_size>;
using Vtep = std::array<std::byte, vtep_size>;

inline constexpr std::uint32_t max_vni = 0x00FF'FFFF;  // 24-bit Geneve VNI

// Largest body a message can carry (mctp::max_message_size less the vendor header).
inline constexpr std::size_t max_body_size = mctp::max_message_size - mctp::vendor_header_size;

inline constexpr std::size_t prepare_head_size = 16;
inline constexpr std::size_t nic_config_size = 20;
inline constexpr std::size_t blk_config_size = 8;
inline constexpr std::size_t clean_function_size = 4;
inline constexpr std::size_t deliver_key_size = 16 + volume_key_size;
inline constexpr std::size_t drop_key_size = 16;
inline constexpr std::size_t map_chunk_head_size = 8;
inline constexpr std::size_t create_volume_head_size = 32;
inline constexpr std::size_t delete_volume_size = 8;
inline constexpr std::size_t rewrap_volume_head_size = 24;
inline constexpr std::size_t tunnel_key_size = 32;  // X25519 keys and the WireGuard PSK
inline constexpr std::size_t set_tunnel_key_size = tunnel_key_size;
inline constexpr std::size_t set_tunnel_peer_size = vtep_size + (2 * tunnel_key_size);
inline constexpr std::size_t remove_tunnel_peer_size = vtep_size;
// Room for a later wrapped-key format; helm's format 1 is 95 bytes. Equal
// to oar-blk's max_wrapped_key_size (the field in its volume header).
inline constexpr std::size_t max_wrapped_volume_key = 256;
inline constexpr std::size_t image_name_size = 32;  // SHA-256 of an image manifest
using ImageName = std::array<std::byte, image_name_size>;
inline constexpr std::uint32_t sector_size = 512;
// Largest volume a request may describe: its byte size still fits an off_t
// with room for the role's metadata.
inline constexpr std::uint64_t max_capacity_sectors = std::uint64_t{1} << 53U;
inline constexpr std::size_t max_map_chunk = max_body_size - map_chunk_head_size;
// Largest MapUpdate frame (proto::max_map_update_size, format v2: 40-byte
// header, 4096 entries of 32 bytes, 8192 guest IPv4 addresses of 16 bytes
// and 8192 IPv6 of 24, 64-byte signature). Mirrored so this header does not
// depend on ak::proto; tests/oar_protocol_test.cpp pins the two.
inline constexpr std::size_t max_map_frame =
    0x28 + (4096 * 0x20) + (8192 * 0x10) + (8192 * 0x18) + 64;

inline constexpr std::size_t response_head_size = 2;
inline constexpr std::size_t inventory_head_size = 20;
inline constexpr std::size_t inventory_entry_size = 4;
// Bounded so an inventory response fits one message with room to spare.
inline constexpr std::size_t max_inventory_entries = 1000;
inline constexpr std::size_t health_body_size = 8;
// proto::group_policy_size, mirrored; tests/oar_protocol_test.cpp pins it.
inline constexpr std::size_t group_policy_frame_size = 0x80;
inline constexpr std::size_t usage_request_size = 4;
inline constexpr std::size_t usage_head_size = 8;
inline constexpr std::size_t usage_entry_size = 96;
inline constexpr std::size_t max_usage_page = 40;  // 3848 bytes: one message
// proto::max_group_usage_entries, mirrored: one role never meters more.
inline constexpr std::size_t max_usage_entries = 1024;
inline constexpr std::uint8_t usage_detached = 0x01;

// Result of a request. Values are part of the wire protocol: never renumber.
enum class Status : std::uint8_t {
    ok = 0,
    unknown_function = 1,  // no such function on this role
    wrong_type = 2,        // the function is not of the type the request names
    bad_request = 3,       // the request body did not decode
    busy = 4,              // the function is in a state that cannot take the request
    failed = 5,            // the role tried and failed (cleaning error, bad map frame)
    unsupported = 6,       // this role does not implement the operation
};

// Which data-plane role answers on a slot. Values are wire protocol.
enum class Role : std::uint8_t {
    net = 1,
    blk = 2,
    gpu = 3,
};

// Values are wire protocol.
enum class HealthState : std::uint8_t {
    ok = 0,
    degraded = 1,
    faulted = 2,
};

[[nodiscard]] auto to_string(Status s) noexcept -> const char*;
[[nodiscard]] auto to_string(Role r) noexcept -> const char*;
[[nodiscard]] auto to_string(HealthState h) noexcept -> const char*;

// Whether a role may report functions of `type`.
[[nodiscard]] auto role_serves(Role role, FunctionType type) noexcept -> bool;

enum class BodyError : std::uint8_t {
    truncated,          // shorter than the body's fixed size
    trailing_bytes,     // longer than the body's size
    reserved_not_zero,  // a reserved byte is set
    unknown_enum,       // function type, cleaning action, status, role or state out of range
    zero_id,            // vm_id, nic_id or volume_id is zero (ids are never zero)
    bad_vni,            // zero, or wider than 24 bits
    bad_mac,            // not a locally administered unicast MAC
    bad_vtep,           // zero for the net role, non-zero for any other
    type_mismatch,      // config does not match the function type, or role cannot serve it
    not_increasing,     // inventory entries not in strictly increasing fn order
    too_many_entries,   // inventory larger than max_inventory_entries
    bad_chunk,          // map_update total, offset or chunk length out of range
    status_with_body,   // a non-ok response carries bytes after its head
    bad_geometry,       // block size not 512/4096, or capacity zero, ragged or too large
    bad_key_length,     // wrapped key empty, too long, or not the length the body says
    zero_key,           // a tunnel private or public key is all zero
    bad_image,          // an image volume's image name is all zero
};

[[nodiscard]] auto to_string(BodyError e) noexcept -> const char*;

// ---- Requests -------------------------------------------------------------

struct NicConfig {
    NicId nic_id{0};
    std::uint32_t vni{0};
    Mac mac{};

    friend auto operator==(const NicConfig&, const NicConfig&) -> bool = default;
};

struct BlkConfig {
    VolumeId volume_id{0};

    friend auto operator==(const BlkConfig&, const BlkConfig&) -> bool = default;
};

// monostate for GPU functions, which take no configuration.
using FunctionConfig = std::variant<std::monostate, NicConfig, BlkConfig>;

struct PrepareFunction {
    FunctionNumber fn{0};
    FunctionType type{FunctionType::nic_vf};
    VmId vm_id{0};
    FunctionConfig config;

    friend auto operator==(const PrepareFunction&, const PrepareFunction&) -> bool = default;
};

struct CleanFunction {
    FunctionNumber fn{0};
    CleaningAction action{CleaningAction::reset_nic_vf};

    friend auto operator==(const CleanFunction&, const CleanFunction&) -> bool = default;
};

// The key is a view: into the caller's ScopedKey when encoding, into the
// received message when decoding. The receiver copies it into its key slot
// and wipes the message (OarEndpoint does).
struct DeliverKey {
    FunctionNumber fn{0};
    VolumeId volume_id{0};
    std::span<const std::byte, volume_key_size> key;
};

struct DropKey {
    FunctionNumber fn{0};
    VolumeId volume_id{0};

    friend auto operator==(const DropKey&, const DropKey&) -> bool = default;
};

// The storage role's half of CREATE_VOLUME. `wrapped_key` views into the
// caller's blob when encoding, into the message when decoding.
struct CreateVolume {
    VolumeId volume_id{0};
    VmId owner_vm{0};
    std::uint64_t capacity_sectors{0};
    std::uint32_t block_size{sector_size};
    std::span<const std::byte> wrapped_key;
    std::uint16_t image_store{0};  // non-zero: an image volume
    ImageName image_name{};        // set exactly when image_store is
};

struct DeleteVolume {
    VolumeId volume_id{0};

    friend auto operator==(const DeleteVolume&, const DeleteVolume&) -> bool = default;
};

// REWRAP_VOLUME: the new owner and the key helm re-wrapped for it.
struct RewrapVolume {
    VolumeId volume_id{0};
    VmId owner_vm{0};
    std::span<const std::byte> wrapped_key;
};

// The network role's WireGuard keys. The key spans view into the caller's
// buffers when encoding, into the message when decoding; the receiver
// copies them during the call (OarEndpoint wipes the message after).
struct SetTunnelKey {
    std::span<const std::byte, tunnel_key_size> private_key;
};

struct SetTunnelPeer {
    Vtep vtep{};
    std::span<const std::byte, tunnel_key_size> public_key;
    std::span<const std::byte, tunnel_key_size> psk;
};

struct RemoveTunnelPeer {
    Vtep vtep{};

    friend auto operator==(const RemoveTunnelPeer&, const RemoveTunnelPeer&) -> bool = default;
};

// One chunk of a MapUpdate frame. `chunk` views into the message.
struct MapChunk {
    std::uint32_t total{0};
    std::uint32_t offset{0};
    std::span<const std::byte> chunk;
};

[[nodiscard]] auto encode_prepare_function(const PrepareFunction& p)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_prepare_function(std::span<const std::byte> body) noexcept
    -> std::expected<PrepareFunction, BodyError>;

[[nodiscard]] auto encode_clean_function(const CleanFunction& c)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_clean_function(std::span<const std::byte> body) noexcept
    -> std::expected<CleanFunction, BodyError>;

// The returned buffer holds the key: the caller wipes it with secure_zero.
[[nodiscard]] auto encode_deliver_key(const DeliverKey& d)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_deliver_key(std::span<const std::byte> body) noexcept
    -> std::expected<DeliverKey, BodyError>;

[[nodiscard]] auto encode_drop_key(const DropKey& d)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_drop_key(std::span<const std::byte> body) noexcept
    -> std::expected<DropKey, BodyError>;

[[nodiscard]] auto encode_map_chunk(const MapChunk& m)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_map_chunk(std::span<const std::byte> body) noexcept
    -> std::expected<MapChunk, BodyError>;

[[nodiscard]] auto encode_create_volume(const CreateVolume& c)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_create_volume(std::span<const std::byte> body) noexcept
    -> std::expected<CreateVolume, BodyError>;

[[nodiscard]] auto encode_delete_volume(const DeleteVolume& d)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_delete_volume(std::span<const std::byte> body) noexcept
    -> std::expected<DeleteVolume, BodyError>;

[[nodiscard]] auto encode_rewrap_volume(const RewrapVolume& v)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_rewrap_volume(std::span<const std::byte> body) noexcept
    -> std::expected<RewrapVolume, BodyError>;

// The returned buffers of the first two hold keys: the caller wipes them.
[[nodiscard]] auto encode_set_tunnel_key(const SetTunnelKey& k)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_set_tunnel_key(std::span<const std::byte> body) noexcept
    -> std::expected<SetTunnelKey, BodyError>;

[[nodiscard]] auto encode_set_tunnel_peer(const SetTunnelPeer& p)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_set_tunnel_peer(std::span<const std::byte> body) noexcept
    -> std::expected<SetTunnelPeer, BodyError>;

[[nodiscard]] auto encode_remove_tunnel_peer(const RemoveTunnelPeer& r)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_remove_tunnel_peer(std::span<const std::byte> body) noexcept
    -> std::expected<RemoveTunnelPeer, BodyError>;

[[nodiscard]] auto encode_group_policy_frame(std::span<const std::byte> frame)
    -> std::expected<std::vector<std::byte>, BodyError>;
// The frame, a view into the body: exactly group_policy_frame_size bytes.
[[nodiscard]] auto decode_group_policy_frame(std::span<const std::byte> body) noexcept
    -> std::expected<std::span<const std::byte>, BodyError>;

[[nodiscard]] auto encode_usage_request(std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_usage_request(std::span<const std::byte> body) noexcept
    -> std::expected<std::uint16_t, BodyError>;

// function_inventory and health requests have empty bodies.
[[nodiscard]] auto decode_empty(std::span<const std::byte> body) noexcept
    -> std::expected<void, BodyError>;

// ---- Responses ------------------------------------------------------------

struct InventoryEntry {
    FunctionNumber fn{0};
    FunctionType type{FunctionType::nic_vf};

    friend auto operator==(const InventoryEntry&, const InventoryEntry&) -> bool = default;
};

struct Inventory {
    Role role{Role::net};
    Vtep vtep{};
    std::vector<InventoryEntry> functions;  // strictly increasing fn

    friend auto operator==(const Inventory&, const Inventory&) -> bool = default;
};

struct Health {
    HealthState state{HealthState::ok};
    std::uint16_t fault_code{0};
    std::uint32_t uptime_seconds{0};

    friend auto operator==(const Health&, const Health&) -> bool = default;
};

// One NIC attachment's cumulative group meter, as a network role keeps it
// (oar-net VSwitch GroupUsage).
struct UsageEntry {
    NicId nic_id{0};
    std::uint32_t vni{0};
    bool detached{false};
    std::uint64_t attachment{0};
    std::uint64_t frames{0};
    std::uint64_t bytes{0};
    std::uint64_t replicas_remote{0};
    std::uint64_t replica_bytes_remote{0};
    std::uint64_t replicas_local{0};
    std::uint64_t replica_bytes_local{0};
    std::uint64_t drop_policy{0};
    std::uint64_t drop_rate{0};
    std::uint64_t drop_fanout{0};

    friend auto operator==(const UsageEntry&, const UsageEntry&) -> bool = default;
};

struct UsagePage {
    std::uint16_t total{0};  // entries in the whole snapshot
    std::vector<UsageEntry> entries;

    friend auto operator==(const UsagePage&, const UsagePage&) -> bool = default;
};

// The role's side of group_usage paging. `snapshot` is called on cursor 0
// and returns every meter (attached NICs, then final readings of NICs
// detached since its last call, which it forgets). Final readings of a
// snapshot whose last page was never read are carried into the next one.
class UsagePager {
public:
    using Snapshot = std::vector<UsageEntry>;

    template<typename F>
    auto page(std::uint16_t cursor, F&& snapshot) -> std::expected<UsagePage, Status> {
        if (cursor == 0) {
            take(std::forward<F>(snapshot)());
        }
        return serve(cursor);
    }

private:
    auto take(Snapshot fresh) -> void;
    auto serve(std::uint16_t cursor) -> std::expected<UsagePage, Status>;

    Snapshot _snapshot;
    bool _open{false};  // a snapshot whose last page has not been served
};

// A decoded response head. `body` is what follows it, empty unless status is ok.
struct ResponseView {
    Status status{Status::ok};
    std::span<const std::byte> body;
};

// A response with the given status and (only for ok) body.
[[nodiscard]] auto encode_response(Status status, std::span<const std::byte> body = {})
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_response(std::span<const std::byte> response) noexcept
    -> std::expected<ResponseView, BodyError>;

// Inventory and health bodies, as carried after an ok head.
[[nodiscard]] auto encode_inventory(const Inventory& inv)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_inventory(std::span<const std::byte> body)
    -> std::expected<Inventory, BodyError>;

// group_usage page bodies. decode checks the page against the cursor
// it answers.
[[nodiscard]] auto encode_usage_page(const UsagePage& page, std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_usage_page(std::span<const std::byte> body, std::uint16_t cursor)
    -> std::expected<UsagePage, BodyError>;

[[nodiscard]] auto encode_health(const Health& h)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_health(std::span<const std::byte> body) noexcept
    -> std::expected<Health, BodyError>;

}  // namespace ak::helm::oar
