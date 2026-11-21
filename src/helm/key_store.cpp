// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/key_store.hpp"

#include <utility>

namespace ak::helm {

namespace {

auto from_se(SeError e) noexcept -> KeyError {
    switch (e) {
        case SeError::authentication_failed:
            return KeyError::corrupt_key;
        case SeError::wrong_kind:
            return KeyError::wrong_kind;
        case SeError::wrong_vm_key:
            return KeyError::wrong_vm;
        case SeError::random_failure:
        case SeError::crypto_failure:
        case SeError::master_key_io:
        case SeError::master_key_insecure:
        case SeError::master_key_wrong_size:
            break;
    }
    return KeyError::secure_element;
}

}  // namespace

auto to_string(KeyError e) noexcept -> const char* {
    switch (e) {
        case KeyError::invalid_id:
            return "invalid_id";
        case KeyError::unknown_vm:
            return "unknown_vm";
        case KeyError::duplicate_vm:
            return "duplicate_vm";
        case KeyError::unknown_volume:
            return "unknown_volume";
        case KeyError::duplicate_volume:
            return "duplicate_volume";
        case KeyError::wrong_vm:
            return "wrong_vm";
        case KeyError::same_vm:
            return "same_vm";
        case KeyError::wrong_kind:
            return "wrong_kind";
        case KeyError::corrupt_key:
            return "corrupt_key";
        case KeyError::secure_element:
            return "secure_element";
    }
    return "unknown";
}

auto KeyStore::create_vm_key(VmId vm) -> std::expected<void, KeyError> {
    if (vm == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (_vm_keys.contains(vm)) {
        return std::unexpected(KeyError::duplicate_vm);
    }
    auto key = _se->create_vm_key(vm);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    _vm_keys.emplace(vm, std::move(*key));
    return {};
}

auto KeyStore::destroy_vm_key(VmId vm) -> std::expected<std::vector<VolumeId>, KeyError> {
    const auto it = _vm_keys.find(vm);
    if (it == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    auto erased = volumes_of(vm);
    for (const auto volume : erased) {
        _volume_keys.erase(volume);
    }
    _vm_keys.erase(it);
    return erased;
}

auto KeyStore::create_volume_key(VolumeId volume, VmId owner) -> std::expected<void, KeyError> {
    if (volume == 0 || owner == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (_volume_keys.contains(volume)) {
        return std::unexpected(KeyError::duplicate_volume);
    }
    const auto vm = _vm_keys.find(owner);
    if (vm == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    auto key = _se->create_volume_key(vm->second, volume);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    _volume_keys.emplace(volume, std::move(*key));
    return {};
}

auto KeyStore::unwrap_volume_key(VolumeId volume, VmId requester)
    -> std::expected<ScopedKey, KeyError> {
    const auto vol = _volume_keys.find(volume);
    if (vol == _volume_keys.end()) {
        return std::unexpected(KeyError::unknown_volume);
    }
    if (vol->second.owner != requester) {
        return std::unexpected(KeyError::wrong_vm);
    }
    const auto vm = _vm_keys.find(requester);
    if (vm == _vm_keys.end()) {
        // Unreachable through this API: destroy_vm_key drops the VM's volumes.
        return std::unexpected(KeyError::unknown_vm);
    }
    auto key = _se->unwrap_volume_key(vm->second, vol->second);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    return std::move(*key);
}

auto KeyStore::create_ephemeral_key() -> std::expected<ScopedKey, KeyError> {
    auto key = _se->create_ephemeral_key();
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    return std::move(*key);
}

auto KeyStore::rewrap(VolumeId volume, VmId new_owner) -> std::expected<void, KeyError> {
    const auto vol = _volume_keys.find(volume);
    if (vol == _volume_keys.end()) {
        return std::unexpected(KeyError::unknown_volume);
    }
    if (vol->second.owner == new_owner) {
        return std::unexpected(KeyError::same_vm);
    }
    const auto to = _vm_keys.find(new_owner);
    if (to == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    const auto from = _vm_keys.find(vol->second.owner);
    if (from == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    auto key = _se->rewrap_volume_key(from->second, to->second, vol->second);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    vol->second = std::move(*key);
    return {};
}

auto KeyStore::destroy_volume_key(VolumeId volume) -> std::expected<void, KeyError> {
    if (_volume_keys.erase(volume) == 0) {
        return std::unexpected(KeyError::unknown_volume);
    }
    return {};
}

auto KeyStore::import_vm_key(WrappedVmKey key) -> std::expected<void, KeyError> {
    if (key.vm == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (key.key.kind() != KeyKind::vm) {
        return std::unexpected(KeyError::wrong_kind);
    }
    if (_vm_keys.contains(key.vm)) {
        return std::unexpected(KeyError::duplicate_vm);
    }
    const auto vm = key.vm;
    _vm_keys.emplace(vm, std::move(key));
    return {};
}

auto KeyStore::import_volume_key(WrappedVolumeKey key) -> std::expected<void, KeyError> {
    if (key.volume == 0 || key.owner == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (key.key.kind() != KeyKind::volume) {
        return std::unexpected(KeyError::wrong_kind);
    }
    if (_volume_keys.contains(key.volume)) {
        return std::unexpected(KeyError::duplicate_volume);
    }
    if (!_vm_keys.contains(key.owner)) {
        return std::unexpected(KeyError::unknown_vm);
    }
    const auto volume = key.volume;
    _volume_keys.emplace(volume, std::move(key));
    return {};
}

auto KeyStore::find_vm_key(VmId vm) const -> std::optional<WrappedVmKey> {
    const auto it = _vm_keys.find(vm);
    if (it == _vm_keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

auto KeyStore::find_volume_key(VolumeId volume) const -> std::optional<WrappedVolumeKey> {
    const auto it = _volume_keys.find(volume);
    if (it == _volume_keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

auto KeyStore::owner(VolumeId volume) const -> std::optional<VmId> {
    const auto it = _volume_keys.find(volume);
    if (it == _volume_keys.end()) {
        return std::nullopt;
    }
    return it->second.owner;
}

auto KeyStore::volumes_of(VmId vm) const -> std::vector<VolumeId> {
    std::vector<VolumeId> out;
    for (const auto& [volume, key] : _volume_keys) {
        if (key.owner == vm) {
            out.push_back(volume);
        }
    }
    return out;
}

}  // namespace ak::helm
