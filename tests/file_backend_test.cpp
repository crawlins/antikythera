// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 3.1, 3.3, 3.5 and 7.2:
// harbor's file backend. The metadata header round-trips and rejects every
// kind of damage, volume files are sparse and refuse to be overwritten or
// followed through symlinks, I/O stays inside the volume, rewrap changes
// only owner and wrapped key, erase leaves nothing behind, and a guest's
// plaintext written through VirtioBlkFunction never reaches the file.

#define BOOST_TEST_MODULE file_backend_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include <sys/stat.h>

#include "common/wire.hpp"
#include "oar/blk/file_backend.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, MetadataError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, FileError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, BackendError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk
// Boost.Test's customization point for types it cannot print itself.
namespace std {  // NOLINT(cert-dcl58-cpp): boost_test_print_type is found by ADL
auto boost_test_print_type(std::ostream& os, std::byte b) -> std::ostream& {
    return os << "0x" << std::hex << std::to_integer<unsigned>(b) << std::dec;
}
}  // namespace std

namespace blk = ak::oar::blk;
namespace vio = ak::oar::virtio;
using ak::test::unit_timeout_seconds;
using blk::FileBackend;
using blk::FileError;
using blk::MetadataError;
using blk::VolumeMetadata;

namespace {

constexpr std::uint64_t volume_id = 0x1111'2222'3333'4444ULL;
constexpr std::uint64_t owner_a = 0xA;
constexpr std::uint64_t owner_b = 0xB;
constexpr std::uint64_t capacity = 2048;  // 1 MiB
constexpr std::size_t wrapped_size = 95;  // helm's format-1 wrapped volume key
constexpr std::size_t key_len_offset = 10;
constexpr std::size_t block_size_offset = 12;
constexpr std::size_t key_offset = 40;
constexpr std::size_t digest_offset = key_offset + blk::max_wrapped_key_size;
constexpr std::size_t padding_offset = digest_offset + 32;
constexpr std::size_t half_key = blk::xts_key_size / 2;

auto wrapped(std::uint8_t seed, std::size_t n = wrapped_size) -> std::vector<std::byte> {
    std::vector<std::byte> k(n);
    for (std::size_t i = 0; i < n; ++i) {
        k[i] = static_cast<std::byte>(seed + i);
    }
    return k;
}

auto metadata() -> VolumeMetadata {
    return {.volume_id = volume_id,
            .owner_vm = owner_a,
            .capacity_sectors = capacity,
            .logical_block_size = 512,
            .wrapped_key = wrapped(1),
            .image = std::nullopt};
}

// A fresh directory per test, removed afterwards.
class TempDir {
public:
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-blk-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        _path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }
    [[nodiscard]] auto file(const char* name) const -> std::filesystem::path {
        return _path / name;
    }

private:
    std::filesystem::path _path;
};

auto read_file(const std::filesystem::path& p) -> std::vector<std::byte> {
    std::ifstream in{p, std::ios::binary};
    std::vector<char> raw{std::istreambuf_iterator<char>{in}, {}};
    std::vector<std::byte> out(raw.size());
    std::ranges::transform(raw, out.begin(), [](char c) { return static_cast<std::byte>(c); });
    return out;
}

auto patch_file(const std::filesystem::path& p, std::size_t at, std::byte value) -> void {
    std::fstream f{p, std::ios::binary | std::ios::in | std::ios::out};
    f.seekp(static_cast<std::streamoff>(at));
    const char c = static_cast<char>(value);
    f.write(&c, 1);
}

auto encoded() -> std::array<std::byte, blk::metadata_block_size> {
    auto b = blk::encode_metadata(metadata());
    BOOST_REQUIRE(b);
    return *b;
}

auto contains(std::span<const std::byte> hay, std::span<const std::byte> needle) -> bool {
    return !std::ranges::search(hay, needle).empty();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(metadata_codec)

BOOST_AUTO_TEST_CASE(round_trip, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto block = encoded();
    const auto back = blk::decode_metadata(block);
    BOOST_REQUIRE(back);
    BOOST_TEST((*back == metadata()));

    auto m = metadata();
    m.logical_block_size = 4096;
    m.wrapped_key = wrapped(7, blk::max_wrapped_key_size);
    const auto b4k = blk::encode_metadata(m);
    BOOST_REQUIRE(b4k);
    BOOST_TEST((*blk::decode_metadata(*b4k) == m));
}

BOOST_AUTO_TEST_CASE(encode_refuses_bad_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto bad = [](auto mutate) {
        auto m = metadata();
        mutate(m);
        return blk::encode_metadata(m).error();
    };
    BOOST_TEST(bad([](VolumeMetadata& m) { m.volume_id = 0; }) == MetadataError::zero_id);
    BOOST_TEST(bad([](VolumeMetadata& m) { m.owner_vm = 0; }) == MetadataError::zero_id);
    BOOST_TEST(bad([](VolumeMetadata& m) { m.logical_block_size = 1024; }) ==
               MetadataError::bad_block_size);
    BOOST_TEST(bad([](VolumeMetadata& m) { m.capacity_sectors = 0; }) ==
               MetadataError::bad_capacity);
    BOOST_TEST(bad([](VolumeMetadata& m) {
                   m.logical_block_size = 4096;
                   m.capacity_sectors = 9;
               }) == MetadataError::bad_capacity);
    BOOST_TEST(bad([](VolumeMetadata& m) { m.capacity_sectors = ~std::uint64_t{0}; }) ==
               MetadataError::bad_capacity);
    BOOST_TEST(bad([](VolumeMetadata& m) { m.wrapped_key.clear(); }) ==
               MetadataError::bad_key_length);
    BOOST_TEST(bad([](VolumeMetadata& m) {
                   m.wrapped_key = wrapped(1, blk::max_wrapped_key_size + 1);
               }) == MetadataError::bad_key_length);
}

BOOST_AUTO_TEST_CASE(decode_rejects_damage, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = encoded();
    BOOST_TEST(blk::decode_metadata(std::span{good}.first(100)).error() ==
               MetadataError::wrong_size);

    auto flip = [&](std::size_t at) {
        auto b = good;
        b[at] ^= std::byte{0x01};
        return blk::decode_metadata(b).error();
    };
    BOOST_TEST(flip(0) == MetadataError::bad_magic);
    BOOST_TEST(flip(8) == MetadataError::unsupported_version);
    // Every field and the key are covered by the digest.
    BOOST_TEST(flip(key_len_offset) == MetadataError::bad_digest);
    BOOST_TEST(flip(block_size_offset) == MetadataError::bad_digest);
    BOOST_TEST(flip(16) == MetadataError::bad_digest);
    BOOST_TEST(flip(24) == MetadataError::bad_digest);
    BOOST_TEST(flip(32) == MetadataError::bad_digest);
    BOOST_TEST(flip(key_offset + 5) == MetadataError::bad_digest);
    BOOST_TEST(flip(key_offset + wrapped_size) == MetadataError::bad_digest);
    BOOST_TEST(flip(digest_offset) == MetadataError::bad_digest);
    BOOST_TEST(flip(padding_offset) == MetadataError::nonzero_padding);
    BOOST_TEST(flip(blk::metadata_block_size - 1) == MetadataError::nonzero_padding);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(volume_files)

BOOST_AUTO_TEST_CASE(create_then_open, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.file("vol");
    {
        auto created = FileBackend::create(path, metadata());
        BOOST_REQUIRE(created);
        BOOST_TEST((*created)->size_bytes() == capacity * blk::sector_size);
    }
    struct stat st{};
    BOOST_REQUIRE(::stat(path.c_str(), &st) == 0);
    BOOST_TEST((st.st_mode & 0777) == 0600U);
    BOOST_TEST(static_cast<std::uint64_t>(st.st_size) ==
               blk::volume_data_offset + (capacity * blk::sector_size));
    // Sparse: only the header has blocks behind it.
    BOOST_TEST(static_cast<std::uint64_t>(st.st_blocks) * 512U < capacity * blk::sector_size / 4);

    auto opened = FileBackend::open(path);
    BOOST_REQUIRE(opened);
    BOOST_TEST(((*opened)->metadata() == metadata()));
}

BOOST_AUTO_TEST_CASE(create_never_overwrites, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.file("vol");
    BOOST_REQUIRE(FileBackend::create(path, metadata()));
    BOOST_TEST(FileBackend::create(path, metadata()).error().error == FileError::exists);

    auto m = metadata();
    m.owner_vm = 0;
    const auto bad = FileBackend::create(dir.file("other"), m);
    BOOST_TEST(bad.error().error == FileError::bad_metadata);
    BOOST_TEST(bad.error().metadata_error == MetadataError::zero_id);
    BOOST_TEST(!std::filesystem::exists(dir.file("other")));
}

BOOST_AUTO_TEST_CASE(open_refuses_bad_files, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    BOOST_TEST(FileBackend::open(dir.file("missing")).error().error == FileError::not_found);

    const auto path = dir.file("vol");
    BOOST_REQUIRE(FileBackend::create(path, metadata()));

    std::filesystem::create_symlink(path, dir.file("link"));
    BOOST_TEST(FileBackend::open(dir.file("link")).error().error == FileError::not_regular);
    BOOST_TEST(FileBackend::open(dir.file("")).error().error == FileError::io);  // a directory

    std::filesystem::resize_file(path, blk::volume_data_offset + 512);
    BOOST_TEST(FileBackend::open(path).error().error == FileError::size_mismatch);
    std::filesystem::resize_file(path, 100);
    const auto short_file = FileBackend::open(path);
    BOOST_TEST(short_file.error().error == FileError::bad_metadata);
    BOOST_TEST(short_file.error().metadata_error == MetadataError::wrong_size);

    const auto p2 = dir.file("vol2");
    BOOST_REQUIRE(FileBackend::create(p2, metadata()));
    patch_file(p2, 20, std::byte{0x99});
    const auto corrupt = FileBackend::open(p2);
    BOOST_TEST(corrupt.error().error == FileError::bad_metadata);
    BOOST_TEST(corrupt.error().metadata_error == MetadataError::bad_digest);
}

BOOST_AUTO_TEST_CASE(io_stays_inside_the_volume, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.file("vol");
    auto fb = FileBackend::create(path, metadata());
    BOOST_REQUIRE(fb);
    auto& b = **fb;

    const std::vector<std::byte> data(1024, std::byte{0x5C});
    BOOST_REQUIRE(b.write(512, data));
    BOOST_REQUIRE(b.flush());
    std::vector<std::byte> back(1024);
    BOOST_REQUIRE(b.read(512, back));
    BOOST_TEST(back == data, boost::test_tools::per_element());
    // Unwritten space reads as zeros.
    BOOST_REQUIRE(b.read(0, std::span{back}.first(512)));
    BOOST_TEST(std::ranges::all_of(std::span{back}.first(512),
                                   [](std::byte x) { return x == std::byte{0}; }));
    // The data lands after the header, which is untouched.
    const auto file = read_file(path);
    BOOST_TEST(file[blk::volume_data_offset + 512] == std::byte{0x5C});
    BOOST_TEST(blk::decode_metadata(std::span{file}.first(blk::metadata_block_size)).has_value());

    const std::uint64_t size = capacity * blk::sector_size;
    BOOST_TEST(b.write(size - 512, std::span{data}.first(512)).has_value());
    BOOST_TEST(b.write(size - 512, data).error() == blk::BackendError::out_of_range);
    BOOST_TEST(b.read(size, std::span{back}.first(1)).error() == blk::BackendError::out_of_range);
    BOOST_TEST(b.read(~std::uint64_t{0}, back).error() == blk::BackendError::out_of_range);
}

BOOST_AUTO_TEST_CASE(rewrap_changes_owner_and_key_only,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.file("vol");
    {
        auto fb = FileBackend::create(path, metadata());
        BOOST_REQUIRE(fb);
        const std::vector<std::byte> data(512, std::byte{0x77});
        BOOST_REQUIRE((*fb)->write(0, data));
        BOOST_REQUIRE((*fb)->rewrap(owner_b, wrapped(9)));
        BOOST_TEST((*fb)->metadata().owner_vm == owner_b);
        // A bad rewrap changes nothing.
        BOOST_TEST((*fb)->rewrap(0, wrapped(3)).error().metadata_error == MetadataError::zero_id);
        BOOST_TEST((*fb)->metadata().owner_vm == owner_b);
    }
    auto fb = FileBackend::open(path);
    BOOST_REQUIRE(fb);
    auto want = metadata();
    want.owner_vm = owner_b;
    want.wrapped_key = wrapped(9);
    BOOST_TEST(((*fb)->metadata() == want));
    std::vector<std::byte> back(512);
    BOOST_REQUIRE((*fb)->read(0, back));
    BOOST_TEST(back[0] == std::byte{0x77});
    // The old wrapped key is gone from the file.
    BOOST_TEST(!contains(read_file(path), wrapped(1)));
}

BOOST_AUTO_TEST_CASE(erase_removes_everything, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.file("vol");
    BOOST_REQUIRE(FileBackend::create(path, metadata()));
    // Keep a hard link, standing in for blocks the filesystem has not yet
    // reused: the header, and with it the wrapped key, must be wiped.
    std::filesystem::create_hard_link(path, dir.file("shadow"));
    BOOST_REQUIRE(FileBackend::erase(path));
    BOOST_TEST(!std::filesystem::exists(path));
    BOOST_TEST(!contains(read_file(dir.file("shadow")), wrapped(1)));
    BOOST_TEST(FileBackend::erase(path).error().error == FileError::not_found);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(image_volumes)

auto image_metadata(std::size_t key_len = 0) -> VolumeMetadata {
    auto m = metadata();
    m.wrapped_key = wrapped(3, key_len);
    blk::ImageSource src{.store_id = 7, .name = {}};
    for (std::size_t i = 0; i < src.name.size(); ++i) {
        src.name[i] = static_cast<std::byte>(0x50 + i);
    }
    m.image = src;
    return m;
}

// Version 2 puts the image source after the key and the digest after it.
constexpr std::size_t image_store_offset = digest_offset;
constexpr std::size_t image_name_offset = image_store_offset + 8;
constexpr std::size_t image_digest_offset = image_name_offset + blk::image_name_size;

BOOST_AUTO_TEST_CASE(header_round_trips_as_version_2,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const std::size_t key_len : {std::size_t{0}, wrapped_size}) {
        const auto m = image_metadata(key_len);
        const auto block = blk::encode_metadata(m);
        BOOST_REQUIRE(block.has_value());
        BOOST_TEST(std::to_integer<int>((*block)[8]) == blk::metadata_version_image);
        BOOST_TEST(std::to_integer<int>((*block)[image_store_offset]) == 7);
        const auto back = blk::decode_metadata(*block);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == m));
    }
    // A disk volume still encodes as version 1.
    BOOST_TEST(std::to_integer<int>(blk::encode_metadata(metadata()).value()[8]) ==
               blk::metadata_version);
}

BOOST_AUTO_TEST_CASE(header_rejects_bad_image_fields,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto m = image_metadata();
    m.image->store_id = 0;
    BOOST_TEST((blk::encode_metadata(m).error() == MetadataError::bad_image_source));
    m = image_metadata();
    m.image->name = {};
    BOOST_TEST((blk::encode_metadata(m).error() == MetadataError::bad_image_source));
    // Only an image volume may go without a key.
    m = metadata();
    m.wrapped_key.clear();
    BOOST_TEST((blk::encode_metadata(m).error() == MetadataError::bad_key_length));

    const auto good = blk::encode_metadata(image_metadata()).value();
    auto b = good;
    b[image_name_offset] ^= std::byte{1};  // the digest covers the image source
    BOOST_TEST((blk::decode_metadata(b).error() == MetadataError::bad_digest));
    b = good;
    b[image_digest_offset + 32] = std::byte{1};
    BOOST_TEST((blk::decode_metadata(b).error() == MetadataError::nonzero_padding));
    b = good;
    b[8] = std::byte{1};  // a version-2 header read as version 1
    BOOST_TEST((blk::decode_metadata(b).error() == MetadataError::bad_digest));
    b = good;
    b[8] = std::byte{3};
    BOOST_TEST((blk::decode_metadata(b).error() == MetadataError::unsupported_version));
}

BOOST_AUTO_TEST_CASE(file_is_only_the_header, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const TempDir dir;
    const auto path = dir.file("vol.akv");
    const auto m = image_metadata();
    BOOST_REQUIRE(FileBackend::create_image_volume(path, m).has_value());
    BOOST_TEST(std::filesystem::file_size(path) == blk::metadata_block_size);
    const auto back = FileBackend::read_metadata(path);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == m));
    // Not a disk: open() and create() refuse it, and it is never overwritten.
    BOOST_TEST((FileBackend::open(path).error().error == FileError::image_volume));
    BOOST_TEST(
        (FileBackend::create(dir.file("other.akv"), m).error().error == FileError::image_volume));
    BOOST_TEST((FileBackend::create_image_volume(path, m).error().error == FileError::exists));
    BOOST_TEST((FileBackend::create_image_volume(dir.file("disk.akv"), metadata()).error().error ==
                FileError::bad_metadata));
    // A disk volume's file read the same way.
    BOOST_REQUIRE(FileBackend::create(dir.file("disk.akv"), metadata()).has_value());
    BOOST_TEST((FileBackend::read_metadata(dir.file("disk.akv")).value() == metadata()));
    // An image header with data behind it is not an image volume file.
    std::filesystem::resize_file(path, 2 * blk::metadata_block_size);
    BOOST_TEST((FileBackend::read_metadata(path).error().error == FileError::size_mismatch));
    std::filesystem::resize_file(path, blk::metadata_block_size);
    BOOST_REQUIRE(FileBackend::erase(path).has_value());
    BOOST_TEST(!std::filesystem::exists(path));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(with_the_function)

// Requirement 7.2, at unit scale: plaintext in the guest, only ciphertext
// in the backing file, and a reopened volume reads back with the key.
BOOST_AUTO_TEST_CASE(file_holds_only_ciphertext, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.file("vol");
    BOOST_REQUIRE(FileBackend::create(path, metadata()));

    std::array<std::byte, blk::xts_key_size> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(i < half_key ? 0x10 + i : 0x90 + i);
    }
    // A guest pattern that would be easy to find if it leaked.
    std::vector<std::byte> plain(2 * blk::sector_size);
    const std::string marker = "PLAINTEXT-MARKER-";
    for (std::size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<std::byte>(marker[i % marker.size()]);
    }
    const std::vector<std::byte> needle(plain.begin(), plain.begin() + 32);

    auto run = [&](bool write) -> std::vector<std::byte> {
        ak::test::GuestRam ram;
        ak::test::RecordingInterrupts irq;
        auto backend = FileBackend::open(path);
        BOOST_REQUIRE(backend);
        auto fn = blk::VirtioBlkFunction::create({.geometry = {.capacity_sectors = capacity,
                                                               .logical_block_size = 512,
                                                               .seg_max = 4,
                                                               .max_transfer_bytes = 16384},
                                                  .num_queues = 1,
                                                  .queue_size = ak::test::test_queue_size,
                                                  .budget = ak::test::test_queue_size,
                                                  .serial = "vol"},
                                                 ram.memory(), irq, std::move(*backend));
        BOOST_REQUIRE(fn);
        BOOST_REQUIRE((*fn)->deliver_key(key));
        ak::test::VirtioDriver driver{ram, (*fn)->pci()};
        BOOST_REQUIRE(driver.bring_up(vio::feature_bit(vio::feature_version_1), {0}));

        std::vector<vio::Gpa> gpas;
        const auto len = static_cast<std::uint32_t>(plain.size());
        driver.post(0,
                    {{.len = 16, .writable = false},
                     {.len = len, .writable = !write},
                     {.len = 1, .writable = true}},
                    &gpas);
        std::vector<std::byte> hdr;
        ak::wire::Writer w{hdr};
        w.le32(write ? 1 : 0);
        w.le32(0);
        w.le64(64);
        ram.put_bytes(gpas[0], hdr);
        if (write) {
            ram.put_bytes(gpas[1], plain);
        }
        BOOST_REQUIRE(driver.notify(0));
        BOOST_TEST(ram.get<std::byte>(gpas[2]) == std::byte{0});
        return ram.bytes(gpas[1], plain.size());
    };

    static_cast<void>(run(true));
    const auto file = read_file(path);
    BOOST_TEST(!contains(file, needle));
    BOOST_TEST(!contains(file, key));
    const auto stored =
        std::span{file}.subspan(blk::volume_data_offset + (64 * blk::sector_size), plain.size());
    BOOST_TEST(!std::ranges::equal(stored, plain));

    BOOST_TEST(run(false) == plain, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_SUITE_END()
