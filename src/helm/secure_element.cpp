// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/secure_element.hpp"

#include <cerrno>
#include <climits>
#include <memory>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

// Domain separation for the AAD, so these blobs can never be confused with
// any other AES-GCM use of the same key.
constexpr std::string_view aad_label = "antikythera helm key wrap v1";

constexpr int gcm_tag_size = static_cast<int>(WrappedKey::tag_size);
constexpr int gcm_nonce_size = static_cast<int>(WrappedKey::nonce_size);
constexpr mode_t master_key_mode = 0600;
constexpr mode_t group_other_bits = 077;

static_assert(master_key_size == vm_key_size,
              "VM keys and the master key are both AES-256 key-encryption keys");

struct CipherCtxDeleter {
    auto operator()(EVP_CIPHER_CTX* c) const noexcept -> void { EVP_CIPHER_CTX_free(c); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

class Fd {
public:
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&&) = delete;
    auto operator=(Fd&&) -> Fd& = delete;
    ~Fd() {
        if (_fd >= 0) {
            (void)::close(_fd);
        }
    }
    [[nodiscard]] auto get() const noexcept -> int { return _fd; }
    [[nodiscard]] auto valid() const noexcept -> bool { return _fd >= 0; }

private:
    int _fd;
};

auto as_uchar(std::span<const std::byte> b) noexcept -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(b.data());
}

auto as_uchar_mut(std::span<std::byte> b) noexcept -> unsigned char* {
    return reinterpret_cast<unsigned char*>(b.data());
}

auto random_fill(std::span<std::byte> out) -> std::expected<void, SeError> {
    if (RAND_bytes(as_uchar_mut(out), static_cast<int>(out.size())) != 1) {
        ERR_clear_error();
        return std::unexpected(SeError::random_failure);
    }
    return {};
}

}  // namespace

auto SecureElement::create_ephemeral_key() -> std::expected<ScopedKey, SeError> {
    SecretBytes<volume_key_size> key;  // wiped when it goes out of scope
    if (auto ok = random_fill(key.span()); !ok) {
        return std::unexpected(ok.error());
    }
    return make_scoped_key(key.span());
}

namespace {

// What a blob is bound to: the VM for a VM key; the volume and its owner
// for a volume key.
struct Identity {
    KeyKind kind;
    std::uint64_t id;
    std::uint64_t owner;  // volume keys only
};

auto vm_identity(VmId vm) noexcept -> Identity {
    return Identity{.kind = KeyKind::vm, .id = vm, .owner = 0};
}

auto volume_identity(VolumeId volume, VmId owner) noexcept -> Identity {
    return Identity{.kind = KeyKind::volume, .id = volume, .owner = owner};
}

auto encode_header(KeyKind kind) -> std::array<std::byte, WrappedKey::header_size> {
    return {static_cast<std::byte>(WrappedKey::format_version), static_cast<std::byte>(kind),
            static_cast<std::byte>(key_size(kind))};
}

auto build_aad(std::span<const std::byte> header, const Identity& who) -> std::vector<std::byte> {
    std::vector<std::byte> aad;
    wire::Writer w{aad};
    w.bytes(std::as_bytes(std::span{aad_label}));
    w.bytes(header);
    w.be64(who.id);
    if (who.kind == KeyKind::volume) {
        w.be64(who.owner);
    }
    return aad;
}

// AES-256-GCM-wraps `plaintext` (exactly key_size(who.kind) bytes) under `kek`.
auto seal(std::span<const std::byte, vm_key_size> kek, const Identity& who,
          std::span<const std::byte> plaintext) -> std::expected<WrappedKey, SeError> {
    const auto header = encode_header(who.kind);
    std::array<std::byte, WrappedKey::nonce_size> nonce{};
    if (auto r = random_fill(nonce); !r) {
        return std::unexpected(r.error());
    }
    const auto aad = build_aad(header, who);

    std::vector<std::byte> out(WrappedKey::encoded_size(who.kind));
    std::ranges::copy(header, out.begin());
    std::ranges::copy(nonce, out.begin() + WrappedKey::header_size);
    const auto ct =
        std::span{out}.subspan(WrappedKey::header_size + WrappedKey::nonce_size, plaintext.size());
    const auto tag = std::span{out}.last(WrappedKey::tag_size);

    CipherCtx ctx{EVP_CIPHER_CTX_new()};
    int len = 0;
    int final_len = 0;
    const bool ok =
        ctx && EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, gcm_nonce_size, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, as_uchar(kek),
                           as_uchar(std::span<const std::byte>{nonce})) == 1 &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, as_uchar(aad), static_cast<int>(aad.size())) ==
            1 &&
        EVP_EncryptUpdate(ctx.get(), as_uchar_mut(ct), &len, as_uchar(plaintext),
                          static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(ctx.get(), as_uchar_mut(ct.subspan(static_cast<std::size_t>(len))),
                            &final_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, gcm_tag_size, as_uchar_mut(tag)) == 1;
    if (!ok) {
        ERR_clear_error();
        return std::unexpected(SeError::crypto_failure);
    }
    auto wrapped = WrappedKey::decode(out);
    if (!wrapped) {
        return std::unexpected(SeError::crypto_failure);
    }
    return std::move(*wrapped);
}

// Authenticates and decrypts `wrapped` into `out` (key_size(who.kind) bytes).
// `out` is wiped on failure.
auto open_blob(std::span<const std::byte, vm_key_size> kek, const Identity& who,
               const WrappedKey& wrapped, std::span<std::byte> out)
    -> std::expected<void, SeError> {
    if (wrapped.kind() != who.kind || out.size() != key_size(who.kind)) {
        return std::unexpected(SeError::wrong_kind);
    }
    const auto aad = build_aad(wrapped.header(), who);
    const auto ct = wrapped.ciphertext();
    // EVP_CTRL_GCM_SET_TAG takes a non-const pointer but only reads it.
    std::array<std::byte, WrappedKey::tag_size> tag{};
    std::ranges::copy(wrapped.tag(), tag.begin());

    CipherCtx ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) {
        return std::unexpected(SeError::crypto_failure);
    }
    int len = 0;
    const bool setup_ok =
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, gcm_nonce_size, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, as_uchar(kek), as_uchar(wrapped.nonce())) ==
            1 &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, as_uchar(aad), static_cast<int>(aad.size())) ==
            1 &&
        EVP_DecryptUpdate(ctx.get(), as_uchar_mut(out), &len, as_uchar(ct),
                          static_cast<int>(ct.size())) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, gcm_tag_size, as_uchar_mut(tag)) == 1;
    if (!setup_ok) {
        ERR_clear_error();
        secure_zero(out);
        return std::unexpected(SeError::crypto_failure);
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), as_uchar_mut(out.subspan(static_cast<std::size_t>(len))),
                            &final_len) != 1) {
        ERR_clear_error();
        secure_zero(out);
        return std::unexpected(SeError::authentication_failed);
    }
    return {};
}

auto write_all(int fd, std::span<const std::byte> bytes) -> bool {
    while (!bytes.empty()) {
        const auto n = ::write(fd, bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
    return true;
}

auto read_all(int fd, std::span<std::byte> bytes) -> bool {
    while (!bytes.empty()) {
        const auto n = ::read(fd, bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
    return true;
}

// Creates the master key file. Returns false (and creates nothing) if it
// already exists; any other failure is an error.
auto create_master_key_file(const std::filesystem::path& path) -> std::expected<bool, SeError> {
    Fd fd{::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                 master_key_mode)};
    if (!fd.valid()) {
        if (errno == EEXIST) {
            return false;
        }
        return std::unexpected(SeError::master_key_io);
    }
    SecretBytes<master_key_size> key;
    if (auto r = random_fill(key.span()); !r) {
        (void)::unlink(path.c_str());
        return std::unexpected(r.error());
    }
    if (!write_all(fd.get(), key.span()) || ::fsync(fd.get()) != 0) {
        (void)::unlink(path.c_str());
        return std::unexpected(SeError::master_key_io);
    }
    return true;
}

auto read_master_key_file(const std::filesystem::path& path)
    -> std::expected<SecretBytes<master_key_size>, SeError> {
    Fd fd{::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    if (!fd.valid()) {
        // O_NOFOLLOW on a symlink fails with ELOOP: a symlink is refused as
        // insecure, not reported as an I/O error.
        return std::unexpected(errno == ELOOP ? SeError::master_key_insecure
                                              : SeError::master_key_io);
    }
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) {
        return std::unexpected(SeError::master_key_io);
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & group_other_bits) != 0) {
        return std::unexpected(SeError::master_key_insecure);
    }
    if (st.st_size != static_cast<off_t>(master_key_size)) {
        return std::unexpected(SeError::master_key_wrong_size);
    }
    SecretBytes<master_key_size> key;
    if (!read_all(fd.get(), key.span())) {
        return std::unexpected(SeError::master_key_io);
    }
    return key;
}

}  // namespace

auto to_string(WrappedKeyError e) noexcept -> const char* {
    switch (e) {
        case WrappedKeyError::wrong_size:
            return "wrong_size";
        case WrappedKeyError::unsupported_version:
            return "unsupported_version";
        case WrappedKeyError::unknown_kind:
            return "unknown_kind";
        case WrappedKeyError::wrong_key_length:
            return "wrong_key_length";
    }
    return "unknown";
}

auto to_string(SeError e) noexcept -> const char* {
    switch (e) {
        case SeError::random_failure:
            return "random_failure";
        case SeError::crypto_failure:
            return "crypto_failure";
        case SeError::authentication_failed:
            return "authentication_failed";
        case SeError::wrong_kind:
            return "wrong_kind";
        case SeError::wrong_vm_key:
            return "wrong_vm_key";
        case SeError::master_key_io:
            return "master_key_io";
        case SeError::master_key_insecure:
            return "master_key_insecure";
        case SeError::master_key_wrong_size:
            return "master_key_wrong_size";
    }
    return "unknown";
}

auto WrappedKey::decode(std::span<const std::byte> bytes)
    -> std::expected<WrappedKey, WrappedKeyError> {
    wire::Reader r{bytes};
    const auto version = r.u8();
    const auto kind_byte = r.u8();
    const auto key_len = r.u8();
    if (!version || !kind_byte || !key_len) {
        return std::unexpected(WrappedKeyError::wrong_size);
    }
    if (*version != format_version) {
        return std::unexpected(WrappedKeyError::unsupported_version);
    }
    if (*kind_byte != static_cast<std::uint8_t>(KeyKind::vm) &&
        *kind_byte != static_cast<std::uint8_t>(KeyKind::volume)) {
        return std::unexpected(WrappedKeyError::unknown_kind);
    }
    const auto kind = static_cast<KeyKind>(*kind_byte);
    if (*key_len != key_size(kind)) {
        return std::unexpected(WrappedKeyError::wrong_key_length);
    }
    if (bytes.size() != encoded_size(kind)) {
        return std::unexpected(WrappedKeyError::wrong_size);
    }
    return WrappedKey{kind, std::vector<std::byte>(bytes.begin(), bytes.end())};
}

WrappedKey::~WrappedKey() {
    secure_zero(_bytes);
}

auto WrappedKey::header() const noexcept -> std::span<const std::byte, header_size> {
    return std::span{_bytes}.first<header_size>();
}

auto WrappedKey::nonce() const noexcept -> std::span<const std::byte, nonce_size> {
    return std::span{_bytes}.subspan<header_size, nonce_size>();
}

auto WrappedKey::ciphertext() const noexcept -> std::span<const std::byte> {
    return std::span{_bytes}.subspan(header_size + nonce_size, key_size(_kind));
}

auto WrappedKey::tag() const noexcept -> std::span<const std::byte, tag_size> {
    return std::span{_bytes}.last<tag_size>();
}

auto SoftwareSecureElement::open(const std::filesystem::path& path)
    -> std::expected<SoftwareSecureElement, SeError> {
    if (auto created = create_master_key_file(path); !created) {
        return std::unexpected(created.error());
    }
    // Read back even after creating, so a fresh file passes the same checks
    // as an existing one.
    auto master = read_master_key_file(path);
    if (!master) {
        return std::unexpected(master.error());
    }
    return SoftwareSecureElement{std::move(*master)};
}

auto SoftwareSecureElement::ephemeral() -> std::expected<SoftwareSecureElement, SeError> {
    SecretBytes<master_key_size> master;
    if (auto r = random_fill(master.span()); !r) {
        return std::unexpected(r.error());
    }
    return SoftwareSecureElement{std::move(master)};
}

auto SoftwareSecureElement::unwrap_vm_key(const WrappedVmKey& vm) const
    -> std::expected<SecretBytes<vm_key_size>, SeError> {
    SecretBytes<vm_key_size> key;
    if (auto r = open_blob(_master.span(), vm_identity(vm.vm), vm.key, key.span()); !r) {
        return std::unexpected(r.error());
    }
    return key;
}

auto SoftwareSecureElement::create_vm_key(VmId vm) -> std::expected<WrappedVmKey, SeError> {
    SecretBytes<vm_key_size> key;
    if (auto r = random_fill(key.span()); !r) {
        return std::unexpected(r.error());
    }
    auto wrapped = seal(_master.span(), vm_identity(vm), key.span());
    if (!wrapped) {
        return std::unexpected(wrapped.error());
    }
    return WrappedVmKey{.vm = vm, .key = std::move(*wrapped)};
}

auto SoftwareSecureElement::create_volume_key(const WrappedVmKey& owner, VolumeId volume)
    -> std::expected<WrappedVolumeKey, SeError> {
    auto vm_key = unwrap_vm_key(owner);
    if (!vm_key) {
        return std::unexpected(vm_key.error());
    }
    SecretBytes<volume_key_size> key;
    if (auto r = random_fill(key.span()); !r) {
        return std::unexpected(r.error());
    }
    auto wrapped = seal(vm_key->span(), volume_identity(volume, owner.vm), key.span());
    if (!wrapped) {
        return std::unexpected(wrapped.error());
    }
    return WrappedVolumeKey{.volume = volume, .owner = owner.vm, .key = std::move(*wrapped)};
}

auto SoftwareSecureElement::unwrap_volume_key(const WrappedVmKey& owner,
                                              const WrappedVolumeKey& volume)
    -> std::expected<ScopedKey, SeError> {
    if (owner.vm != volume.owner) {
        return std::unexpected(SeError::wrong_vm_key);
    }
    auto vm_key = unwrap_vm_key(owner);
    if (!vm_key) {
        return std::unexpected(vm_key.error());
    }
    SecretBytes<volume_key_size> key;
    if (auto r = open_blob(vm_key->span(), volume_identity(volume.volume, volume.owner), volume.key,
                           key.span());
        !r) {
        return std::unexpected(r.error());
    }
    return make_scoped_key(key.span());
}

auto SoftwareSecureElement::rewrap_volume_key(const WrappedVmKey& from, const WrappedVmKey& to,
                                              const WrappedVolumeKey& volume)
    -> std::expected<WrappedVolumeKey, SeError> {
    if (from.vm != volume.owner) {
        return std::unexpected(SeError::wrong_vm_key);
    }
    auto from_key = unwrap_vm_key(from);
    if (!from_key) {
        return std::unexpected(from_key.error());
    }
    auto to_key = unwrap_vm_key(to);
    if (!to_key) {
        return std::unexpected(to_key.error());
    }
    SecretBytes<volume_key_size> key;
    if (auto r = open_blob(from_key->span(), volume_identity(volume.volume, volume.owner),
                           volume.key, key.span());
        !r) {
        return std::unexpected(r.error());
    }
    auto wrapped = seal(to_key->span(), volume_identity(volume.volume, to.vm), key.span());
    if (!wrapped) {
        return std::unexpected(wrapped.error());
    }
    return WrappedVolumeKey{.volume = volume.volume, .owner = to.vm, .key = std::move(*wrapped)};
}

}  // namespace ak::helm
