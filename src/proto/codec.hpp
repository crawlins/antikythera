// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Shared pieces of the controller wire formats (.kiro/specs/controller-interface/):
// the error type, the Ed25519 sizes, and the key ID rule.
//
// src/proto/ is header-only and depends only on src/common/wire.hpp, so the
// controller (kythira's EC2 module) can include it without linking any
// antikythera library. It encodes and decodes frames and says which bytes
// are signed; it never signs or verifies. Signing is the controller's job
// (kythira's HSM/KMS) and verification is the receiver's (hull for slots,
// helm/oar-net for mapping updates), each with its own Ed25519
// implementation.
//
// All multi-byte fields are little-endian, matching the mailbox slot.

#include <cstddef>
#include <cstdint>

#include "common/wire.hpp"

namespace ak::proto {

// Controller signing key ID (Requirement 1.3). 0 means "unsigned" and is
// never valid on a frame the controller signs, as in the mailbox slot.
using KeyId = std::uint16_t;
inline constexpr KeyId no_key_id = 0;

inline constexpr std::size_t ed25519_signature_size = 64;

enum class DecodeError : std::uint8_t {
    truncated,                // the frame ended before a field did
    trailing_bytes,           // bytes after the end of the frame
    bad_magic,                //
    bad_version,              // a frame format version this code does not speak
    bad_key_id,               // key_id is no_key_id
    key_id_mismatch,          // envelope key_id differs from the slot header's key_id
    bad_server_id,            // server_id 0 (never allocated)
    reserved_not_zero,        // a reserved byte is non-zero
    bad_vni,                  // VNI 0 or wider than 24 bits
    bad_map_version,          // mapping version 0 (versions start at 1)
    too_many_entries,         // more than max_map_entries
    bad_nic_id,               // NIC ID 0
    nic_ids_not_ascending,    // entries not in strictly increasing NIC ID order
    bad_mac,                  // MAC not a locally administered unicast address
    bad_vtep,                 // owner VTEP address unspecified (all zero) or multicast
    bad_report_seq,           // report sequence number 0
    bad_boot_id,              // inventory boot ID 0
    bad_id,                   // a VM, volume or command identifier that must be non-zero is 0
    unknown_value,            // an enum field holds a value the protocol does not define
    bad_capacity,             // a free count larger than its total
    not_ascending,            // a list that must be in strictly increasing key order is not
    bad_owner,                // a function's owner VM disagrees with its state
    bad_record_type,          // a link record type this code does not speak
    record_too_large,         // a link record longer than max_record_payload
    too_many_addresses,       // more than max_guest_addresses of one family
    bad_guest_address,        // a guest address that is not unicast
    addresses_not_ascending,  // guest addresses not in strictly increasing order
    unknown_address_nic,      // a guest address owned by a NIC not in the mapping
    server_id_mismatch,       // envelope server_id differs from the slot header's server_id
    bad_policy_version,       // group policy version 0 (versions start at 1)
    bad_group_limits,         // group policy limits that do not fit its mode or bounds
    bad_epoch,                // volume epoch 0 (epochs start at 1)
    bad_block_size,           // a volume block size other than 512 or 4096
    bad_member,               // a replica member with no endpoint, port or replica_gen
    bad_roles,                // replica roles break the one-primary rule
    too_many_members,         // no members, or more than max_replica_members
    too_many_attachments,     // more than max_volume_attachments
    bad_attachment_mode,      // more than one read-write attachment without multi_attach
    bad_qos,                  // a QoS limit of 0, or a burst below its baseline
    bad_source,               // a volume source whose fields do not fit its kind
    bad_header_crc,           // a hold frame header whose CRC32C does not match
    bad_block_range,          // a block count or LBA range a hold opcode does not allow
    bad_payload_size,         // a hold payload whose length does not fit its opcode
    bad_hold_direction,       // a hold flag or status that does not fit the opcode's direction
};

[[nodiscard]] inline constexpr auto to_string(DecodeError e) noexcept -> const char* {
    switch (e) {
        case DecodeError::truncated:
            return "truncated";
        case DecodeError::trailing_bytes:
            return "trailing bytes";
        case DecodeError::bad_magic:
            return "bad magic";
        case DecodeError::bad_version:
            return "unsupported format version";
        case DecodeError::bad_key_id:
            return "missing key id";
        case DecodeError::key_id_mismatch:
            return "envelope key id differs from slot key id";
        case DecodeError::bad_server_id:
            return "server id 0";
        case DecodeError::server_id_mismatch:
            return "envelope server id differs from slot server id";
        case DecodeError::reserved_not_zero:
            return "reserved bytes not zero";
        case DecodeError::bad_vni:
            return "VNI 0 or wider than 24 bits";
        case DecodeError::bad_map_version:
            return "mapping version 0";
        case DecodeError::too_many_entries:
            return "too many mapping entries";
        case DecodeError::bad_nic_id:
            return "NIC id 0";
        case DecodeError::nic_ids_not_ascending:
            return "NIC ids not strictly ascending";
        case DecodeError::bad_mac:
            return "MAC not locally administered unicast";
        case DecodeError::bad_vtep:
            return "owner VTEP unspecified or multicast";
        case DecodeError::bad_report_seq:
            return "report sequence 0";
        case DecodeError::bad_boot_id:
            return "boot id 0";
        case DecodeError::bad_id:
            return "identifier 0";
        case DecodeError::unknown_value:
            return "unknown enum value";
        case DecodeError::bad_capacity:
            return "free count exceeds total";
        case DecodeError::not_ascending:
            return "list not strictly ascending";
        case DecodeError::bad_owner:
            return "function owner disagrees with its state";
        case DecodeError::bad_record_type:
            return "unknown link record type";
        case DecodeError::record_too_large:
            return "link record too large";
        case DecodeError::too_many_addresses:
            return "too many guest addresses";
        case DecodeError::bad_guest_address:
            return "guest address not unicast";
        case DecodeError::addresses_not_ascending:
            return "guest addresses not strictly ascending";
        case DecodeError::unknown_address_nic:
            return "guest address owned by a NIC not in the mapping";
        case DecodeError::bad_policy_version:
            return "group policy version 0";
        case DecodeError::bad_group_limits:
            return "group policy limits do not fit its mode";
        case DecodeError::bad_epoch:
            return "volume epoch 0";
        case DecodeError::bad_block_size:
            return "block size not 512 or 4096";
        case DecodeError::bad_member:
            return "replica member without endpoint, port or replica generation";
        case DecodeError::bad_roles:
            return "replica roles break the one-primary rule";
        case DecodeError::too_many_members:
            return "no replica members, or too many";
        case DecodeError::too_many_attachments:
            return "too many volume attachments";
        case DecodeError::bad_attachment_mode:
            return "several read-write attachments without multi-attach";
        case DecodeError::bad_qos:
            return "QoS limit 0 or burst below baseline";
        case DecodeError::bad_source:
            return "volume source fields do not fit its kind";
        case DecodeError::bad_header_crc:
            return "hold header checksum mismatch";
        case DecodeError::bad_block_range:
            return "block range not allowed for the hold opcode";
        case DecodeError::bad_payload_size:
            return "hold payload length does not fit its opcode";
        case DecodeError::bad_hold_direction:
            return "hold flags or status do not fit the opcode";
    }
    return "unknown";
}

}  // namespace ak::proto
