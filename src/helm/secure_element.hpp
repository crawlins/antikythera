// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The secure element behind helm's key hierarchy
// (.kiro/specs/helm-control-plane/ Requirement 4):
//
//   master key (never leaves the secure element)
//     └─ VM key       wrapped by the master key, bound to vm_id
//          └─ volume key  wrapped by its owner's VM key, bound to
//                         (volume_id, owner vm_id)
//
// Every operation takes wrapped keys in and gives wrapped keys out, so a
// plaintext VM key exists only inside the secure element. The one
// plaintext that leaves is a volume key, as a ScopedKey that only OarLink
// can read.
//
// Wrapping is AES-256-GCM with a fresh random 96-bit nonce. The additional
// authenticated data binds the blob's header and its identity (vm_id, or
// volume_id and owner), so a wrapped volume key copied onto another volume,
// or presented as another VM's, fails authentication: moving a volume
// between VMs needs an explicit rewrap (Requirement 4.7).
//
// Wrapped key wire format (stored by helm and on the media, so untrusted):
//
//   version u8 (1) | kind u8 | key_len u8 | nonce[12] | ciphertext[key_len] | tag[16]
//
// kind 1 = VM key (key_len 32), kind 2 = volume key (key_len 64).
//
// SoftwareSecureElement is the harbor stand-in: the master key is a 32-byte
// file, created 0600 on first use and refused if anyone else can read it.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <utility>
#include <vector>

#include "helm/device_pool.hpp"
#include "helm/scoped_key.hpp"

namespace ak::helm {

using VolumeId = std::uint64_t;

inline constexpr std::size_t master_key_size = 32;
inline constexpr std::size_t vm_key_size = 32;

// Values are stored in wrapped keys: never renumber.
enum class KeyKind : std::uint8_t {
    vm = 1,
    volume = 2,
};

[[nodiscard]] constexpr auto key_size(KeyKind k) noexcept -> std::size_t {
    return k == KeyKind::vm ? vm_key_size : volume_key_size;
}

enum class WrappedKeyError : std::uint8_t {
    wrong_size,           // not the exact size its header implies
    unsupported_version,  // version byte is not 1
    unknown_kind,         // kind byte is not a KeyKind
    wrong_key_length,     // key_len does not match the kind
};

[[nodiscard]] auto to_string(WrappedKeyError e) noexcept -> const char*;

// A validated wrapped-key blob. Holds the encoded bytes; the ciphertext is
// useless without the wrapping key, but the bytes are still wiped on
// destruction so a destroyed key does not linger in helm's memory.
class WrappedKey {
public:
    static constexpr std::uint8_t format_version = 1;
    static constexpr std::size_t header_size = 3;
    static constexpr std::size_t nonce_size = 12;
    static constexpr std::size_t tag_size = 16;

    [[nodiscard]] static constexpr auto encoded_size(KeyKind k) noexcept -> std::size_t {
        return header_size + nonce_size + key_size(k) + tag_size;
    }

    [[nodiscard]] static auto decode(std::span<const std::byte> bytes)
        -> std::expected<WrappedKey, WrappedKeyError>;

    WrappedKey(const WrappedKey&) = default;
    auto operator=(const WrappedKey&) -> WrappedKey& = default;
    WrappedKey(WrappedKey&&) noexcept = default;
    auto operator=(WrappedKey&&) noexcept -> WrappedKey& = default;
    ~WrappedKey();

    [[nodiscard]] auto kind() const noexcept -> KeyKind { return _kind; }
    [[nodiscard]] auto bytes() const noexcept -> std::span<const std::byte> { return _bytes; }
    [[nodiscard]] auto header() const noexcept -> std::span<const std::byte, header_size>;
    [[nodiscard]] auto nonce() const noexcept -> std::span<const std::byte, nonce_size>;
    [[nodiscard]] auto ciphertext() const noexcept -> std::span<const std::byte>;
    [[nodiscard]] auto tag() const noexcept -> std::span<const std::byte, tag_size>;

    friend auto operator==(const WrappedKey& a, const WrappedKey& b) -> bool {
        return a._bytes == b._bytes;
    }

private:
    WrappedKey(KeyKind kind, std::vector<std::byte> bytes) noexcept
        : _kind{kind}, _bytes{std::move(bytes)} {}

    KeyKind _kind;
    std::vector<std::byte> _bytes;
};

struct WrappedVmKey {
    VmId vm{0};
    WrappedKey key;
};

struct WrappedVolumeKey {
    VolumeId volume{0};
    VmId owner{0};
    WrappedKey key;
};

enum class SeError : std::uint8_t {
    random_failure,         // the RNG failed; nothing was created
    crypto_failure,         // OpenSSL failed outside authentication
    authentication_failed,  // wrong wrapping key, wrong identity, or tampered blob
    wrong_kind,             // a VM key where a volume key belongs, or vice versa
    wrong_vm_key,           // the VM key given is not the volume's owner's
    master_key_io,          // master key file could not be read or written
    master_key_insecure,    // master key file is not a 0600-or-tighter regular file
    master_key_wrong_size,  // master key file is not exactly master_key_size bytes
};

[[nodiscard]] auto to_string(SeError e) noexcept -> const char*;

class SecureElement {
public:
    SecureElement() = default;
    SecureElement(const SecureElement&) = delete;
    auto operator=(const SecureElement&) -> SecureElement& = delete;
    virtual ~SecureElement() = default;

    // Generates a VM key and returns it wrapped by the master key.
    virtual auto create_vm_key(VmId vm) -> std::expected<WrappedVmKey, SeError> = 0;

    // Generates a volume key and returns it wrapped by `owner`'s VM key.
    virtual auto create_volume_key(const WrappedVmKey& owner, VolumeId volume)
        -> std::expected<WrappedVolumeKey, SeError> = 0;

    // Unwraps a volume key for delivery to its storage role.
    virtual auto unwrap_volume_key(const WrappedVmKey& owner, const WrappedVolumeKey& volume)
        -> std::expected<ScopedKey, SeError> = 0;

    // Re-wraps `volume` from `from` (its current owner) to `to`, without the
    // volume key leaving the secure element.
    virtual auto rewrap_volume_key(const WrappedVmKey& from, const WrappedVmKey& to,
                                   const WrappedVolumeKey& volume)
        -> std::expected<WrappedVolumeKey, SeError> = 0;

    // Draws a fresh random volume key that is never wrapped or stored: an
    // image volume's attachment key (oar-blk Requirement 8.6), gone once
    // delivered. The default draws it from OpenSSL's RNG.
    virtual auto create_ephemeral_key() -> std::expected<ScopedKey, SeError>;

protected:
    SecureElement(SecureElement&&) noexcept = default;
    auto operator=(SecureElement&&) noexcept -> SecureElement& = default;

    // ScopedKey's constructor is private to this base, so every
    // implementation creates keys through here.
    [[nodiscard]] static auto make_scoped_key(std::span<const std::byte, volume_key_size> key)
        -> ScopedKey {
        return ScopedKey{key};
    }
};

class SoftwareSecureElement final : public SecureElement {
public:
    // Opens the master key file at `path`, creating it (0600, random) if it
    // does not exist. Refuses symlinks, non-regular files, files readable or
    // writable by group or others, and files of the wrong size.
    [[nodiscard]] static auto open(const std::filesystem::path& path)
        -> std::expected<SoftwareSecureElement, SeError>;

    // A random master key held only in memory (tests, throwaway harbor runs).
    [[nodiscard]] static auto ephemeral() -> std::expected<SoftwareSecureElement, SeError>;

    SoftwareSecureElement(SoftwareSecureElement&&) noexcept = default;
    auto operator=(SoftwareSecureElement&&) noexcept -> SoftwareSecureElement& = default;
    ~SoftwareSecureElement() override = default;

    auto create_vm_key(VmId vm) -> std::expected<WrappedVmKey, SeError> override;
    auto create_volume_key(const WrappedVmKey& owner, VolumeId volume)
        -> std::expected<WrappedVolumeKey, SeError> override;
    auto unwrap_volume_key(const WrappedVmKey& owner, const WrappedVolumeKey& volume)
        -> std::expected<ScopedKey, SeError> override;
    auto rewrap_volume_key(const WrappedVmKey& from, const WrappedVmKey& to,
                           const WrappedVolumeKey& volume)
        -> std::expected<WrappedVolumeKey, SeError> override;

private:
    explicit SoftwareSecureElement(SecretBytes<master_key_size> master) noexcept
        : _master{std::move(master)} {}

    [[nodiscard]] auto unwrap_vm_key(const WrappedVmKey& vm) const
        -> std::expected<SecretBytes<vm_key_size>, SeError>;

    SecretBytes<master_key_size> _master;
};

}  // namespace ak::helm
