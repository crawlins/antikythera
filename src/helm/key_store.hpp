// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// KeyStore: helm's table of wrapped VM and volume keys, in front of the
// secure element (.kiro/specs/helm-control-plane/ Requirement 4 and the
// KeyStore section of design.md).
//
// It enforces the hierarchy's rules:
//   - a volume's key unwraps only for the VM that owns it (4.4);
//   - moving a volume needs rewrap(), never a silent owner change (4.7);
//   - destroy_volume_key() forgets the wrapped key (DELETE_VOLUME, 4.6);
//   - destroy_vm_key() forgets the VM key and every volume key it wraps,
//     crypto-erasing them, for DESTROY_VM with persist_volumes = false (4.6).
//
// The KeyStore holds only wrapped keys; the plaintext volume key it hands
// out is a ScopedKey only OarLink can read (4.5). The import_* and find_*
// calls let helm persist the wrapped keys (VM keys on helm's own storage,
// volume keys on the media) and reload them after a restart; imported blobs
// are authenticated on first use, not on import.

#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <vector>

#include "helm/secure_element.hpp"

namespace ak::helm {

enum class KeyError : std::uint8_t {
    invalid_id,  // vm_id or volume_id is zero (ids are never zero)
    unknown_vm,
    duplicate_vm,
    unknown_volume,
    duplicate_volume,
    wrong_vm,        // the VM asking for a volume key does not own it
    same_vm,         // rewrap to the volume's current owner
    wrong_kind,      // an imported blob of the wrong KeyKind
    corrupt_key,     // a wrapped key failed authentication
    secure_element,  // the secure element failed (RNG, crypto)
};

[[nodiscard]] auto to_string(KeyError e) noexcept -> const char*;

class KeyStore {
public:
    // `se` must outlive the KeyStore.
    explicit KeyStore(SecureElement& se) noexcept : _se{&se} {}

    auto create_vm_key(VmId vm) -> std::expected<void, KeyError>;
    // Forgets the VM key and every volume key wrapped by it. Returns those
    // volumes, now crypto-erased, in id order.
    auto destroy_vm_key(VmId vm) -> std::expected<std::vector<VolumeId>, KeyError>;

    auto create_volume_key(VolumeId volume, VmId owner) -> std::expected<void, KeyError>;
    auto unwrap_volume_key(VolumeId volume, VmId requester) -> std::expected<ScopedKey, KeyError>;
    auto rewrap(VolumeId volume, VmId new_owner) -> std::expected<void, KeyError>;
    auto destroy_volume_key(VolumeId volume) -> std::expected<void, KeyError>;
    // A fresh key for one attachment of an image volume, never wrapped or
    // kept (SecureElement::create_ephemeral_key).
    auto create_ephemeral_key() -> std::expected<ScopedKey, KeyError>;

    // Reload persisted wrapped keys. A volume key's owner must already be
    // known.
    auto import_vm_key(WrappedVmKey key) -> std::expected<void, KeyError>;
    auto import_volume_key(WrappedVolumeKey key) -> std::expected<void, KeyError>;

    [[nodiscard]] auto find_vm_key(VmId vm) const -> std::optional<WrappedVmKey>;
    [[nodiscard]] auto find_volume_key(VolumeId volume) const -> std::optional<WrappedVolumeKey>;
    [[nodiscard]] auto owner(VolumeId volume) const -> std::optional<VmId>;
    [[nodiscard]] auto volumes_of(VmId vm) const -> std::vector<VolumeId>;
    [[nodiscard]] auto vm_count() const noexcept -> std::size_t { return _vm_keys.size(); }
    [[nodiscard]] auto volume_count() const noexcept -> std::size_t { return _volume_keys.size(); }

private:
    SecureElement* _se;
    std::map<VmId, WrappedVmKey> _vm_keys;
    std::map<VolumeId, WrappedVolumeKey> _volume_keys;
};

}  // namespace ak::helm
