// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirement 8.8, task 12: pack_image
// turns a raw image into a manifest and a sparse data object, plaintext or
// encrypted under an image key; zero chunks become holes; the result is
// deterministic; bad options and short images are refused; and a packed
// image reads back through LazyImageBackend as the original bytes.

#define BOOST_TEST_MODULE image_pack_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oar/blk/chunk_cache.hpp"
#include "oar/blk/fetcher.hpp"
#include "oar/blk/file_io.hpp"
#include "oar/blk/image_manifest.hpp"
#include "oar/blk/image_pack.hpp"
#include "oar/blk/lazy_image_backend.hpp"
#include "oar/blk/object_store.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, PackError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk

namespace blk = ak::oar::blk;
using ak::test::unit_timeout_seconds;
using Clock = blk::ObjectStore::Clock;

namespace {

constexpr std::uint8_t shift = blk::min_chunk_shift;
constexpr std::uint64_t chunk_bytes = std::uint64_t{1} << shift;
constexpr std::size_t half_key = 32;

// An in-memory file, so tests need no directory.
class MemFile {
public:
    MemFile() : _fd{::memfd_create("ak-image-pack-test", MFD_CLOEXEC)} { BOOST_REQUIRE(_fd >= 0); }
    explicit MemFile(std::span<const std::byte> bytes) : MemFile() {
        BOOST_REQUIRE(blk::file_io::pwrite_all(_fd, bytes, 0).has_value());
    }
    MemFile(const MemFile&) = delete;
    auto operator=(const MemFile&) -> MemFile& = delete;
    MemFile(MemFile&&) = delete;
    auto operator=(MemFile&&) -> MemFile& = delete;
    ~MemFile() { ::close(_fd); }

    [[nodiscard]] auto fd() const -> int { return _fd; }
    [[nodiscard]] auto contents() const -> std::vector<std::byte> {
        struct stat st{};
        BOOST_REQUIRE(::fstat(_fd, &st) == 0);
        std::vector<std::byte> out(static_cast<std::size_t>(st.st_size));
        BOOST_REQUIRE(blk::file_io::pread_all(_fd, out, 0).has_value());
        return out;
    }

private:
    int _fd;
};

auto make_key(std::uint8_t seed) -> std::array<std::byte, blk::xts_key_size> {
    std::array<std::byte, blk::xts_key_size> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(seed + (i < half_key ? i : 0x80 + i));
    }
    return key;
}

auto key_id(std::uint8_t first) -> blk::ImageKeyId {
    blk::ImageKeyId id{};
    id[0] = std::byte{first};
    return id;
}

// `chunks` chunks (the last one `tail` bytes when non-zero), with the
// chunks in `zero` all zeros.
auto make_raw(std::uint32_t chunks, std::uint64_t tail, const std::vector<std::uint32_t>& zero)
    -> std::vector<std::byte> {
    const std::uint64_t size = ((chunks - 1) * chunk_bytes) + (tail == 0 ? chunk_bytes : tail);
    std::vector<std::byte> raw(size);
    for (std::size_t i = 0; i < size; ++i) {
        raw[i] = static_cast<std::byte>(((i / 512) * 31) + (i % 251) + 1);
    }
    for (const auto z : zero) {
        const auto from = z * chunk_bytes;
        std::fill_n(raw.begin() + static_cast<std::ptrdiff_t>(from),
                    static_cast<std::ptrdiff_t>(std::min(chunk_bytes, size - from)), std::byte{0});
    }
    return raw;
}

auto plain_options() -> blk::PackOptions {
    return {.logical_block_size = 512, .chunk_shift = shift, .image_key = {}, .key_id = {}};
}

auto chunk_of(const std::vector<std::byte>& v, const blk::ImageManifest& m, std::uint32_t c)
    -> std::span<const std::byte> {
    return std::span{v}.subspan(m.chunk_offset(c), m.chunk_length(c));
}

// A read-only store over the packed objects.
class MemoryStore final : public blk::ObjectStore {
public:
    auto put(const std::string& key, std::vector<std::byte> bytes) -> void {
        const std::scoped_lock lock{_mutex};
        _objects[key] = std::move(bytes);
    }
    auto get_range(std::string_view key, std::uint64_t offset, std::span<std::byte> out,
                   Clock::time_point /*deadline*/)
        -> std::expected<void, blk::FetchError> override {
        const std::scoped_lock lock{_mutex};
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end() || offset > it->second.size() ||
            out.size() > it->second.size() - offset) {
            return std::unexpected(blk::FetchError::not_found);
        }
        std::copy_n(it->second.begin() + static_cast<std::ptrdiff_t>(offset), out.size(),
                    out.begin());
        return {};
    }
    auto get(std::string_view key, std::size_t max_bytes, Clock::time_point /*deadline*/)
        -> std::expected<std::vector<std::byte>, blk::FetchError> override {
        const std::scoped_lock lock{_mutex};
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end()) {
            return std::unexpected(blk::FetchError::not_found);
        }
        if (it->second.size() > max_bytes) {
            return std::unexpected(blk::FetchError::too_large);
        }
        return it->second;
    }

private:
    std::mutex _mutex;
    std::map<std::string, std::vector<std::byte>> _objects;
};

class TempDir {
public:
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-pack-XXXXXX").string();
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
    [[nodiscard]] auto path() const -> const std::filesystem::path& { return _path; }

private:
    std::filesystem::path _path;
};

// Packs `raw`, publishes it to a store, opens it as an image volume and
// returns what the guest reads for the whole volume (decrypted with K_eph).
auto read_back(const std::vector<std::byte>& raw, const blk::PackOptions& options,
               std::optional<blk::XtsKey> image_key) -> std::vector<std::byte> {
    const MemFile in{raw};
    const MemFile data;
    const auto packed = blk::pack_image(in.fd(), raw.size(), data.fd(), options);
    BOOST_REQUIRE(packed.has_value());

    MemoryStore store;
    const auto hex = blk::image_name_hex(packed->name);
    store.put(blk::image_manifest_key("images", hex), packed->manifest_bytes);
    store.put(blk::image_data_key("images", hex), data.contents());
    const auto manifest_bytes = store.get(blk::image_manifest_key("images", hex), 1U << 26U,
                                          Clock::now() + std::chrono::seconds{1});
    BOOST_REQUIRE(manifest_bytes.has_value());
    const auto manifest = blk::decode_named_manifest(*manifest_bytes, packed->name);
    BOOST_REQUIRE(manifest.has_value());

    const TempDir dir;
    auto cache = blk::ChunkCache::create(dir.path(), 16 * chunk_bytes);
    BOOST_REQUIRE(cache.has_value());
    auto fetcher = blk::Fetcher::create(store, {.workers = 2,
                                                .deadline = std::chrono::milliseconds{2000},
                                                .attempts = 3,
                                                .backoff = std::chrono::milliseconds{1},
                                                .max_queued_prefetch = 8});
    auto image = (*cache)->open_image(packed->name, *manifest, blk::image_data_key("images", hex));
    BOOST_REQUIRE(image.has_value());
    auto backend = blk::LazyImageBackend::create({.image = *image,
                                                  .fetcher = fetcher.get(),
                                                  .overlay_dir = dir.path(),
                                                  .capacity_bytes = raw.size(),
                                                  .logical_block_size = 512,
                                                  .overlay_limit_bytes = 0,
                                                  .max_readahead_chunks = 2,
                                                  .waker = nullptr});
    BOOST_REQUIRE(backend.has_value());
    const auto eph = make_key(0x40);
    BOOST_REQUIRE((*backend)->load_keys(eph, image_key).has_value());

    std::vector<std::byte> cipher(raw.size());
    BOOST_REQUIRE((*backend)->read(0, cipher).has_value());
    auto c = blk::XtsCipher::create(eph, 512);
    BOOST_REQUIRE(c.has_value());
    std::vector<std::byte> plain(raw.size());
    BOOST_REQUIRE(c->decrypt(0, cipher, plain).has_value());
    return plain;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(image_pack)

BOOST_AUTO_TEST_CASE(packs_a_plain_image_with_holes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto raw = make_raw(5, 3 * 512, {1, 3});
    const MemFile in{raw};
    const MemFile data;
    const auto packed = blk::pack_image(in.fd(), raw.size(), data.fd(), plain_options());
    BOOST_REQUIRE(packed.has_value());
    const auto& m = packed->manifest;

    BOOST_TEST(!m.encrypted);
    BOOST_TEST(m.image_bytes == raw.size());
    BOOST_TEST(m.chunk_count() == 5U);
    BOOST_TEST(packed->stored_chunks == 3U);
    BOOST_TEST(m.is_hole(1));
    BOOST_TEST(m.is_hole(3));
    // The manifest bytes decode to the manifest, and name it.
    const auto decoded = blk::decode_named_manifest(packed->manifest_bytes, packed->name);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST((*decoded == m));
    // The data object is the image, byte for byte, and every stored chunk
    // matches its digest.
    const auto stored = data.contents();
    BOOST_TEST((stored == raw));
    for (std::uint32_t c = 0; c < m.chunk_count(); ++c) {
        BOOST_TEST(blk::chunk_matches(m, c, chunk_of(stored, m, c)) == !m.is_hole(c));
    }
}

BOOST_AUTO_TEST_CASE(leaves_holes_unwritten, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Two stored chunks around 30 zero chunks: the data object should
    // allocate about two chunks' worth, not 32.
    std::vector<std::uint32_t> zero;
    for (std::uint32_t c = 1; c < 31; ++c) {
        zero.push_back(c);
    }
    const auto raw = make_raw(32, 0, zero);
    const MemFile in{raw};
    const MemFile data;
    const auto packed = blk::pack_image(in.fd(), raw.size(), data.fd(), plain_options());
    BOOST_REQUIRE(packed.has_value());
    BOOST_TEST(packed->stored_chunks == 2U);
    struct stat st{};
    BOOST_REQUIRE(::fstat(data.fd(), &st) == 0);
    BOOST_TEST(static_cast<std::uint64_t>(st.st_size) == raw.size());
    BOOST_TEST(static_cast<std::uint64_t>(st.st_blocks) * 512 <= 4 * chunk_bytes);
}

BOOST_AUTO_TEST_CASE(encrypts_under_the_image_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto raw = make_raw(4, 0, {2});
    const auto key = make_key(0x11);
    auto options = plain_options();
    options.image_key = blk::XtsKey{key};
    options.key_id = key_id(9);
    const MemFile in{raw};
    const MemFile data;
    const auto packed = blk::pack_image(in.fd(), raw.size(), data.fd(), options);
    BOOST_REQUIRE(packed.has_value());
    const auto& m = packed->manifest;
    BOOST_TEST(m.encrypted);
    BOOST_TEST((m.key_id == key_id(9)));
    BOOST_TEST(m.is_hole(2));  // still a hole: plaintext zeros are never stored

    // The stored chunks are ciphertext: block n under tweak n.
    const auto stored = data.contents();
    auto c = blk::XtsCipher::create(key, 512);
    BOOST_REQUIRE(c.has_value());
    for (const std::uint32_t chunk : {0U, 1U, 3U}) {
        const auto piece = chunk_of(stored, m, chunk);
        BOOST_TEST(!std::ranges::equal(piece, chunk_of(raw, m, chunk)));
        BOOST_TEST(blk::chunk_matches(m, chunk, piece));
        std::vector<std::byte> plain(piece.size());
        BOOST_REQUIRE(c->decrypt(m.chunk_offset(chunk) / 512, piece, plain).has_value());
        BOOST_TEST(std::ranges::equal(plain, chunk_of(raw, m, chunk)));
    }
    BOOST_TEST(
        std::ranges::all_of(chunk_of(stored, m, 2), [](std::byte b) { return b == std::byte{0}; }));
}

BOOST_AUTO_TEST_CASE(is_deterministic, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto raw = make_raw(3, 512, {1});
    const auto pack = [&](const blk::PackOptions& o) {
        const MemFile in{raw};
        const MemFile data;
        auto p = blk::pack_image(in.fd(), raw.size(), data.fd(), o);
        BOOST_REQUIRE(p.has_value());
        return p->name;
    };
    BOOST_TEST((pack(plain_options()) == pack(plain_options())));
    // Different geometry, different image.
    auto bigger = plain_options();
    bigger.chunk_shift = shift + 1;
    BOOST_TEST((pack(plain_options()) != pack(bigger)));
}

BOOST_AUTO_TEST_CASE(uses_4k_blocks, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto raw = make_raw(2, 4096, {});
    const auto key = make_key(0x22);
    auto options = plain_options();
    options.logical_block_size = 4096;
    options.image_key = blk::XtsKey{key};
    options.key_id = key_id(1);
    const MemFile in{raw};
    const MemFile data;
    const auto packed = blk::pack_image(in.fd(), raw.size(), data.fd(), options);
    BOOST_REQUIRE(packed.has_value());
    BOOST_TEST(packed->manifest.logical_block_size == 4096U);
    auto c = blk::XtsCipher::create(key, 4096);
    BOOST_REQUIRE(c.has_value());
    const auto stored = data.contents();
    std::vector<std::byte> plain(stored.size());
    BOOST_REQUIRE(c->decrypt(0, stored, plain).has_value());
    BOOST_TEST((plain == raw));
}

BOOST_AUTO_TEST_CASE(refuses_bad_options_and_sizes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto raw = make_raw(1, 0, {});
    const MemFile in{raw};
    const auto pack = [&](std::uint64_t size, const blk::PackOptions& o) {
        const MemFile data;
        return blk::pack_image(in.fd(), size, data.fd(), o);
    };
    auto o = plain_options();
    o.logical_block_size = 1024;
    BOOST_TEST(pack(raw.size(), o).error() == blk::PackError::bad_options);
    o = plain_options();
    o.chunk_shift = blk::min_chunk_shift - 1;
    BOOST_TEST(pack(raw.size(), o).error() == blk::PackError::bad_options);
    o.chunk_shift = blk::max_chunk_shift + 1;
    BOOST_TEST(pack(raw.size(), o).error() == blk::PackError::bad_options);
    // A key needs a key ID, and a key ID needs a key.
    const auto key = make_key(0x33);
    o = plain_options();
    o.image_key = blk::XtsKey{key};
    BOOST_TEST(pack(raw.size(), o).error() == blk::PackError::bad_options);
    o = plain_options();
    o.key_id = key_id(1);
    BOOST_TEST(pack(raw.size(), o).error() == blk::PackError::bad_options);

    BOOST_TEST(pack(0, plain_options()).error() == blk::PackError::bad_image_size);
    BOOST_TEST(pack(raw.size() - 1, plain_options()).error() == blk::PackError::bad_image_size);
    o = plain_options();
    o.logical_block_size = 4096;
    BOOST_TEST(pack(raw.size() - 512, o).error() == blk::PackError::bad_image_size);
    // Checked before anything is read, so the size need not be real.
    BOOST_TEST(
        pack((std::uint64_t{blk::max_image_chunks} + 1) * chunk_bytes, plain_options()).error() ==
        blk::PackError::too_many_chunks);
    // An image shorter than its stated size.
    BOOST_TEST(pack(raw.size() + chunk_bytes, plain_options()).error() ==
               blk::PackError::read_failed);
}

BOOST_AUTO_TEST_CASE(reads_back_through_an_image_volume,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto raw = make_raw(6, 7 * 512, {2, 4});
    BOOST_TEST((read_back(raw, plain_options(), std::nullopt) == raw));

    const auto key = make_key(0x55);
    auto options = plain_options();
    options.image_key = blk::XtsKey{key};
    options.key_id = key_id(3);
    BOOST_TEST((read_back(raw, options, blk::XtsKey{key}) == raw));
}

BOOST_AUTO_TEST_SUITE_END()
