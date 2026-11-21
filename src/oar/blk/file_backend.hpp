// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// harbor's volume store: one sparse file per volume, a metadata header in
// front of the ciphertext (.kiro/specs/oar-blk-data-plane/ Requirement 3.1,
// design "Backend").
//
//   offset 0     4 KiB metadata block (VolumeMetadata, below)
//   offset 4096  volume data: capacity_sectors * 512 bytes of ciphertext,
//                sparse until written
//
// The data starts on a 4 KiB boundary so both logical block sizes stay
// aligned in the file. The header holds the volume key only in wrapped
// form, as helm produced it (AES-256-GCM under the owner's VM key, bound
// to the volume and owner IDs); oar-blk treats it as opaque bytes and helm
// authenticates it on unwrap. The file never holds plaintext data or an
// unwrapped key.
//
// The header is read back from disk, so it is untrusted input: it is
// decoded with ak::wire, every field is checked, and a SHA-256 digest over
// the encoded fields catches corruption before helm ever sees the wrapped
// key. A file whose size does not match the capacity it claims is refused.
//
// An image volume (Requirement 8, task 13) is only this header: version 2,
// naming the image (object store ID and image name) instead of holding
// ciphertext. Its data is the image under a throwaway overlay, served by
// LazyImageBackend; the file is exactly metadata_block_size bytes. A plain
// image's volume has no wrapped key; an encrypted image's will hold the
// image key wrapped by helm (task 15).
//
// Deleting a volume (Requirement 3.3) is crypto-erase plus release: helm
// destroys its copy of the wrapped key, and erase() overwrites the header
// (the only copy left here), syncs, and unlinks the file. Without the key
// the ciphertext that may linger in freed blocks is unreadable.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "oar/blk/virtio_blk_function.hpp"

namespace ak::oar::blk {

inline constexpr std::size_t metadata_block_size = 4096;
inline constexpr std::uint64_t volume_data_offset = metadata_block_size;
// helm's wrapped volume key is 95 bytes today (format 1); leave room for
// a later format without changing this layout.
inline constexpr std::size_t max_wrapped_key_size = 256;
inline constexpr std::uint16_t metadata_version = 1;
inline constexpr std::uint16_t metadata_version_image = 2;
inline constexpr std::size_t image_name_size = 32;  // SHA-256 of the image manifest

// Where an image volume's base image lives.
struct ImageSource {
    std::uint16_t store_id{0};  // a store the role is configured with; never zero
    std::array<std::byte, image_name_size> name{};  // never all zero

    friend auto operator==(const ImageSource&, const ImageSource&) -> bool = default;
};

struct VolumeMetadata {
    std::uint64_t volume_id{0};             // controller-assigned, never zero
    std::uint64_t owner_vm{0};              // never zero; changes only with REWRAP_VOLUME
    std::uint64_t capacity_sectors{0};      // 512-byte sectors
    std::uint32_t logical_block_size{512};  // 512 or 4096, fixed at creation
    // 1..max_wrapped_key_size bytes; 0..max_wrapped_key_size for an image
    // volume (none for a plain image).
    std::vector<std::byte> wrapped_key;
    std::optional<ImageSource> image;  // set exactly for an image volume (version 2)

    friend auto operator==(const VolumeMetadata&, const VolumeMetadata&) -> bool = default;
};

enum class MetadataError : std::uint8_t {
    wrong_size,  // not exactly metadata_block_size bytes
    bad_magic,   // not an oar-blk volume
    unsupported_version,
    bad_digest,        // the SHA-256 over the fields does not match
    zero_id,           // volume_id or owner_vm is zero
    bad_block_size,    // not 512 or 4096
    bad_capacity,      // zero, not whole logical blocks, or data end overflows
    bad_key_length,    // wrapped key empty or longer than max_wrapped_key_size
    nonzero_padding,   // bytes after the fields are not all zero
    bad_image_source,  // an image volume's store ID is zero or its image name all zero
    crypto_failure,    // OpenSSL could not compute the digest
};

[[nodiscard]] auto to_string(MetadataError e) noexcept -> const char*;

[[nodiscard]] auto encode_metadata(const VolumeMetadata& m)
    -> std::expected<std::array<std::byte, metadata_block_size>, MetadataError>;
[[nodiscard]] auto decode_metadata(std::span<const std::byte> block)
    -> std::expected<VolumeMetadata, MetadataError>;

enum class FileError : std::uint8_t {
    bad_metadata,   // see metadata_error()
    exists,         // create(): the path already exists
    not_found,      // open()/erase(): no such file
    not_regular,    // a symlink, directory or device: refused
    size_mismatch,  // the file is not header + capacity bytes long
    io,             // a system call failed; see os_error()
    image_volume,   // create()/open(): an image volume has no data to serve here
};

[[nodiscard]] auto to_string(FileError e) noexcept -> const char*;

// A failed FileBackend operation, with the detail behind it.
struct FileFailure {
    FileError error{FileError::io};
    MetadataError metadata_error{MetadataError::wrong_size};  // when bad_metadata
    int os_error{0};                                          // errno when io
};

class FileBackend final : public BlockBackend {
public:
    // Creates a new volume file (never overwrites; mode 0600), writes the
    // header, sizes it sparsely to hold the whole volume and syncs it.
    [[nodiscard]] static auto create(const std::filesystem::path& path, const VolumeMetadata& m)
        -> std::expected<std::unique_ptr<FileBackend>, FileFailure>;
    // Opens an existing volume file and validates its header and size.
    // An image volume is refused (image_volume): read_metadata() it.
    [[nodiscard]] static auto open(const std::filesystem::path& path)
        -> std::expected<std::unique_ptr<FileBackend>, FileFailure>;
    // Creates an image volume's file: the version-2 header and nothing
    // else (never overwrites; mode 0600), synced. `m.image` must be set.
    [[nodiscard]] static auto create_image_volume(const std::filesystem::path& path,
                                                  const VolumeMetadata& m)
        -> std::expected<void, FileFailure>;
    // Reads and validates any volume file's header (and its size against
    // it) without opening the volume.
    [[nodiscard]] static auto read_metadata(const std::filesystem::path& path)
        -> std::expected<VolumeMetadata, FileFailure>;
    // Crypto-erase and release: overwrites the header, syncs, unlinks.
    // The volume must not be open.
    [[nodiscard]] static auto erase(const std::filesystem::path& path)
        -> std::expected<void, FileFailure>;

    FileBackend(const FileBackend&) = delete;
    auto operator=(const FileBackend&) -> FileBackend& = delete;
    FileBackend(FileBackend&&) = delete;
    auto operator=(FileBackend&&) -> FileBackend& = delete;
    ~FileBackend() override;

    [[nodiscard]] auto metadata() const noexcept -> const VolumeMetadata& { return _metadata; }

    // REWRAP_VOLUME (Requirement 3.5): the new owner and the key helm
    // re-wrapped for it. Volume ID, capacity and block size cannot change.
    // The 4 KiB header is rewritten with one pwrite and synced.
    [[nodiscard]] auto rewrap(std::uint64_t owner_vm, std::span<const std::byte> wrapped_key)
        -> std::expected<void, FileFailure>;

    // BlockBackend: volume byte offsets, translated past the header.
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override;
    [[nodiscard]] auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, BackendError> override;
    [[nodiscard]] auto write(std::uint64_t offset, std::span<const std::byte> in)
        -> std::expected<void, BackendError> override;
    [[nodiscard]] auto flush() -> std::expected<void, BackendError> override;

private:
    FileBackend(int fd, VolumeMetadata m) noexcept : _fd{fd}, _metadata{std::move(m)} {}

    [[nodiscard]] auto in_range(std::uint64_t offset, std::size_t len) const noexcept -> bool;

    int _fd{-1};
    VolumeMetadata _metadata;
};

}  // namespace ak::oar::blk
