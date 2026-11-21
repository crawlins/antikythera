// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 8.1-8.7, 8.10 and 7.3:
// image volumes over an in-memory object store. The chunk cache keeps
// verified chunks under a budget and evicts least recently used ones; the
// fetcher verifies, retries, joins duplicate fetches and gives up at its
// deadline; the overlay keeps writes and forgets them on discard; and
// LazyImageBackend serves overlay, image and zero blocks as ciphertext
// under the attachment key, fetches only what is read, reads ahead on
// sequential reads and discards the overlay with the key, including
// through VirtioBlkFunction as a guest sees it. Submitted reads that miss
// park until Fetcher::fetch_async delivers and poll() completes them
// (block-volume-service task 3).

#define BOOST_TEST_MODULE image_volume_test
#include <poll.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
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
#include <thread>
#include <vector>

#include "common/wire.hpp"
#include "oar/blk/chunk_cache.hpp"
#include "oar/blk/fetcher.hpp"
#include "oar/blk/image_manifest.hpp"
#include "oar/blk/lazy_image_backend.hpp"
#include "oar/blk/object_store.hpp"
#include "oar/blk/overlay.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, FetchError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, OverlayError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, BackendError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, ImageKeyError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, LazyImageError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk
namespace std {  // NOLINT(cert-dcl58-cpp): boost_test_print_type is found by ADL
auto boost_test_print_type(std::ostream& os, std::byte b) -> std::ostream& {
    return os << "0x" << std::hex << std::to_integer<unsigned>(b) << std::dec;
}
}  // namespace std

namespace blk = ak::oar::blk;
namespace vio = ak::oar::virtio;
using ak::test::unit_timeout_seconds;
using blk::FetchError;
using Clock = blk::ObjectStore::Clock;

namespace {

constexpr std::uint64_t chunk_bytes = 64ULL * 1024;  // chunk shift 16
constexpr std::size_t half_key = 32;

// A store in memory that counts requests and fails on demand.
class MemoryStore final : public blk::ObjectStore {
public:
    auto put(const std::string& key, std::vector<std::byte> bytes) -> void {
        const std::scoped_lock lock{_mutex};
        _objects[key] = std::move(bytes);
    }

    auto get_range(std::string_view key, std::uint64_t offset, std::span<std::byte> out,
                   Clock::time_point deadline) -> std::expected<void, FetchError> override {
        {
            const std::scoped_lock lock{_mutex};
            ++_ranges;
            ++_by_offset[offset];
        }
        if (delay.count() > 0) {
            std::this_thread::sleep_for(delay);
            if (Clock::now() >= deadline) {
                return std::unexpected(FetchError::timed_out);
            }
        }
        const std::scoped_lock lock{_mutex};
        if (fail_next > 0) {
            --fail_next;
            return std::unexpected(fail_with);
        }
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end() || offset > it->second.size() ||
            out.size() > it->second.size() - offset) {
            return std::unexpected(FetchError::not_found);
        }
        std::copy_n(it->second.begin() + static_cast<std::ptrdiff_t>(offset), out.size(),
                    out.begin());
        if (corrupt_next > 0) {
            --corrupt_next;
            out[0] ^= std::byte{1};
        }
        return {};
    }

    auto get(std::string_view key, std::size_t max_bytes, Clock::time_point /*deadline*/)
        -> std::expected<std::vector<std::byte>, FetchError> override {
        const std::scoped_lock lock{_mutex};
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end()) {
            return std::unexpected(FetchError::not_found);
        }
        if (it->second.size() > max_bytes) {
            return std::unexpected(FetchError::too_large);
        }
        return it->second;
    }

    [[nodiscard]] auto ranges() const -> std::uint64_t {
        const std::scoped_lock lock{_mutex};
        return _ranges;
    }
    [[nodiscard]] auto gets_at(std::uint64_t offset) const -> std::uint64_t {
        const std::scoped_lock lock{_mutex};
        const auto it = _by_offset.find(offset);
        return it == _by_offset.end() ? 0 : it->second;
    }

    // Read under _mutex inside get_range; set before fetching.
    unsigned fail_next{0};
    FetchError fail_with{FetchError::io};
    unsigned corrupt_next{0};
    std::chrono::milliseconds delay{0};

private:
    mutable std::mutex _mutex;
    std::map<std::string, std::vector<std::byte>> _objects;
    std::uint64_t _ranges{0};
    std::map<std::uint64_t, std::uint64_t> _by_offset;
};

class TempDir {
public:
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-img-XXXXXX").string();
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

auto make_key(std::uint8_t seed) -> std::array<std::byte, blk::xts_key_size> {
    std::array<std::byte, blk::xts_key_size> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(seed + (i < half_key ? i : 0x80 + i));
    }
    return key;
}

// An image of `chunks` chunks (the last `tail` bytes long when non-zero);
// the chunks listed in `holes` are zeros and stored as holes. Plaintext
// unless `image_key` is given.
struct TestImage {
    std::vector<std::byte> plain;
    std::vector<std::byte> stored;
    blk::ImageManifest manifest;
    blk::ImageDigest name{};
    std::string data_key;
};

auto make_image(MemoryStore& store, std::uint32_t chunks, std::uint64_t tail,
                const std::vector<std::uint32_t>& holes = {},
                const std::array<std::byte, blk::xts_key_size>* image_key = nullptr) -> TestImage {
    TestImage img;
    const std::uint64_t size = ((chunks - 1) * chunk_bytes) + (tail == 0 ? chunk_bytes : tail);
    img.plain.resize(size);
    for (std::size_t i = 0; i < size; ++i) {
        img.plain[i] = static_cast<std::byte>(((i / 512) * 31) + (i % 251) + 1);
    }
    for (const auto h : holes) {
        const auto from = static_cast<std::ptrdiff_t>(h * chunk_bytes);
        const auto len =
            static_cast<std::ptrdiff_t>(std::min(chunk_bytes, size - (h * chunk_bytes)));
        std::fill_n(img.plain.begin() + from, len, std::byte{0});
    }
    img.stored = img.plain;
    img.manifest.chunk_shift = blk::min_chunk_shift;
    img.manifest.image_bytes = size;
    if (image_key != nullptr) {
        img.manifest.encrypted = true;
        img.manifest.key_id[0] = std::byte{7};
        auto c = blk::XtsCipher::create(*image_key, 512);
        BOOST_REQUIRE(c.has_value());
        BOOST_REQUIRE(c->encrypt(0, img.plain, img.stored).has_value());
    }
    for (std::uint32_t c = 0; c < chunks; ++c) {
        if (std::ranges::find(holes, c) != holes.end()) {
            img.manifest.chunks.push_back(blk::ImageDigest{});
            continue;
        }
        const auto piece = std::span{img.stored}.subspan(
            c * chunk_bytes, std::min(chunk_bytes, size - (c * chunk_bytes)));
        img.manifest.chunks.push_back(*blk::sha256_digest(piece));
    }
    const auto bytes = blk::encode_manifest(img.manifest);
    BOOST_REQUIRE(bytes.has_value());
    img.name = *blk::sha256_digest(*bytes);
    const auto hex = blk::image_name_hex(img.name);
    img.data_key = blk::image_data_key("images", hex);
    store.put(blk::image_manifest_key("images", hex), *bytes);
    store.put(img.data_key, img.stored);
    return img;
}

auto fast_config() -> blk::FetcherConfig {
    return {.workers = 2,
            .deadline = std::chrono::milliseconds{2000},
            .attempts = 3,
            .backoff = std::chrono::milliseconds{1},
            .max_queued_prefetch = 8};
}

// Everything one image volume needs.
struct Rig {
    MemoryStore store;
    TempDir dir;
    TestImage image;
    std::unique_ptr<blk::ChunkCache> cache;
    std::unique_ptr<blk::Fetcher> fetcher;
    std::shared_ptr<blk::CachedImage> cached;

    explicit Rig(std::uint32_t chunks, std::uint64_t tail = 0,
                 const std::vector<std::uint32_t>& holes = {},
                 const std::array<std::byte, blk::xts_key_size>* image_key = nullptr,
                 std::uint64_t budget = 64 * chunk_bytes, blk::FetcherConfig config = fast_config())
        : image{make_image(store, chunks, tail, holes, image_key)} {
        auto c = blk::ChunkCache::create(dir.path(), budget);
        BOOST_REQUIRE(c.has_value());
        cache = std::move(*c);
        fetcher = blk::Fetcher::create(store, config);
        auto ci = cache->open_image(image.name, image.manifest, image.data_key);
        BOOST_REQUIRE(ci.has_value());
        cached = *ci;
    }

    auto backend(std::uint64_t capacity, std::uint64_t overlay_limit = 0,
                 std::uint32_t readahead = 0) -> std::unique_ptr<blk::LazyImageBackend> {
        auto b = blk::LazyImageBackend::create({.image = cached,
                                                .fetcher = fetcher.get(),
                                                .overlay_dir = dir.path(),
                                                .capacity_bytes = capacity,
                                                .logical_block_size = 512,
                                                .overlay_limit_bytes = overlay_limit,
                                                .max_readahead_chunks = readahead});
        BOOST_REQUIRE(b.has_value());
        return std::move(*b);
    }
};

// What the function would see: decrypt the backend's output with K_eph.
auto guest_view(std::span<const std::byte> cipher, std::uint64_t offset,
                const std::array<std::byte, blk::xts_key_size>& key) -> std::vector<std::byte> {
    auto c = blk::XtsCipher::create(key, 512);
    BOOST_REQUIRE(c.has_value());
    std::vector<std::byte> out(cipher.size());
    BOOST_REQUIRE(c->decrypt(offset / 512, cipher, out).has_value());
    return out;
}

auto encrypt_for(std::span<const std::byte> plain, std::uint64_t offset,
                 const std::array<std::byte, blk::xts_key_size>& key) -> std::vector<std::byte> {
    auto c = blk::XtsCipher::create(key, 512);
    BOOST_REQUIRE(c.has_value());
    std::vector<std::byte> out(plain.size());
    BOOST_REQUIRE(c->encrypt(offset / 512, plain, out).has_value());
    return out;
}

auto slice(const std::vector<std::byte>& v, std::uint64_t from, std::uint64_t len)
    -> std::vector<std::byte> {
    return {v.begin() + static_cast<std::ptrdiff_t>(from),
            v.begin() + static_cast<std::ptrdiff_t>(from + len)};
}

constexpr int wake_wait_ms = 100;
constexpr int max_wakes = 100;

// The role's event loop in miniature: sleep on `fd`, then poll, until
// `idle` holds.
template<typename Poll, typename Idle> auto run_loop(int fd, Poll poll_once, Idle idle) -> void {
    BOOST_REQUIRE(fd >= 0);
    for (int i = 0; i < max_wakes && !idle(); ++i) {
        pollfd p{.fd = fd, .events = POLLIN, .revents = 0};
        static_cast<void>(::poll(&p, 1, wake_wait_ms));
        static_cast<void>(poll_once());
    }
    BOOST_REQUIRE(idle());
}

auto settle(blk::LazyImageBackend& b) -> void {
    run_loop(b.wake_fd(), [&] { return b.poll(); }, [&] { return b.parked() == 0; });
}

// A submitted read's outcome, once its completion has run.
struct Outcome {
    bool ran{false};
    blk::BackendResult result;
    auto completion() -> blk::BackendCompletion {
        return [this](blk::BackendResult r) {
            BOOST_TEST(!ran);  // exactly once
            ran = true;
            result = r;
        };
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(chunk_cache)

BOOST_AUTO_TEST_CASE(keeps_chunks_and_evicts_the_oldest,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{4, 0, {}, nullptr, 2 * chunk_bytes};
    auto& img = *rig.cached;
    const auto chunk = [&](std::uint32_t c) {
        return slice(rig.image.stored, c * chunk_bytes, chunk_bytes);
    };
    BOOST_TEST(!img.resident(0));
    BOOST_TEST(img.insert(0, chunk(0)));
    BOOST_TEST(img.insert(1, chunk(1)));
    BOOST_TEST(rig.cache->used_bytes() == 2 * chunk_bytes);
    // Touch 0, so 1 is the oldest when 2 needs room.
    std::vector<std::byte> out(100);
    BOOST_TEST(img.read(0, 10, out));
    BOOST_TEST((out == slice(rig.image.stored, 10, 100)));
    BOOST_TEST(img.insert(2, chunk(2)));
    BOOST_TEST(img.resident(0));
    BOOST_TEST(!img.resident(1));
    BOOST_TEST(img.resident(2));
    BOOST_TEST(!img.read(1, 0, out));
    BOOST_TEST(rig.cache->used_bytes() == 2 * chunk_bytes);
    const auto n = rig.cache->counters();
    BOOST_TEST(n.evicted == 1U);
    BOOST_TEST(n.hits == 1U);
    BOOST_TEST(n.misses == 1U);
    // Wrong length, out of range and past-the-chunk reads are refused.
    const auto c3 = chunk(3);
    BOOST_TEST(!img.insert(3, std::span{c3}.subspan(1)));
    BOOST_TEST(!img.insert(9, chunk(3)));
    BOOST_TEST(!img.read(0, chunk_bytes - 50, out));
}

BOOST_AUTO_TEST_CASE(images_are_shared_by_name, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    auto again = rig.cache->open_image(rig.image.name, rig.image.manifest, rig.image.data_key);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(again->get() == rig.cached.get());
    BOOST_TEST(rig.cached->insert(0, slice(rig.image.stored, 0, chunk_bytes)));
    // Dropping the last holder gives the image's chunks back to the budget.
    again->reset();
    rig.cached.reset();
    BOOST_TEST(rig.cache->used_bytes() == 0U);
    auto fresh = rig.cache->open_image(rig.image.name, rig.image.manifest, rig.image.data_key);
    BOOST_REQUIRE(fresh.has_value());
    BOOST_TEST(!(*fresh)->resident(0));
}

BOOST_AUTO_TEST_CASE(refuses_what_cannot_fit, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2, 0, {}, nullptr, chunk_bytes - 1};
    BOOST_TEST(!rig.cached->insert(0, slice(rig.image.stored, 0, chunk_bytes)));
    BOOST_TEST(rig.cache->counters().refused == 1U);
    BOOST_TEST(rig.cache->used_bytes() == 0U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(fetcher)

BOOST_AUTO_TEST_CASE(fetches_verifies_and_caches,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{3, 4096};
    auto got = rig.fetcher->fetch(rig.cached, 2);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST(((**got) == slice(rig.image.stored, 2 * chunk_bytes, 4096)));
    BOOST_TEST(rig.cached->resident(2));
    BOOST_TEST(rig.store.ranges() == 1U);
    BOOST_TEST(rig.fetcher->counters().fetched == 1U);
}

BOOST_AUTO_TEST_CASE(retries_corruption_and_errors,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    rig.store.corrupt_next = 1;
    rig.store.fail_next = 0;
    auto got = rig.fetcher->fetch(rig.cached, 0);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST(rig.fetcher->counters().corrupt == 1U);
    BOOST_TEST(rig.fetcher->counters().retries == 1U);
    BOOST_TEST(rig.store.ranges() == 2U);

    rig.store.fail_next = 2;
    BOOST_TEST(rig.fetcher->fetch(rig.cached, 1).has_value());
    BOOST_TEST(rig.store.ranges() == 5U);
}

BOOST_AUTO_TEST_CASE(gives_up_and_never_caches_bad_data,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    rig.store.corrupt_next = 10;
    auto got = rig.fetcher->fetch(rig.cached, 0);
    BOOST_REQUIRE(!got.has_value());
    BOOST_TEST(got.error() == FetchError::corrupt);
    BOOST_TEST(!rig.cached->resident(0));
    BOOST_TEST(rig.store.ranges() == 3U);  // attempts

    // not_found and denied are final.
    rig.store.corrupt_next = 0;
    rig.store.fail_next = 1;
    rig.store.fail_with = FetchError::denied;
    got = rig.fetcher->fetch(rig.cached, 1);
    BOOST_REQUIRE(!got.has_value());
    BOOST_TEST(got.error() == FetchError::denied);
    BOOST_TEST(rig.store.ranges() == 4U);
    // Holes and chunks past the end are never fetched.
    Rig holes{2, 0, {1}};
    BOOST_TEST(holes.fetcher->fetch(holes.cached, 1).error() == FetchError::not_found);
    BOOST_TEST(holes.fetcher->fetch(holes.cached, 2).error() == FetchError::not_found);
    BOOST_TEST(holes.store.ranges() == 0U);
}

BOOST_AUTO_TEST_CASE(stops_at_the_deadline, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto config = fast_config();
    config.deadline = std::chrono::milliseconds{100};
    Rig rig{1, 0, {}, nullptr, 64 * chunk_bytes, config};
    rig.store.delay = std::chrono::milliseconds{150};
    const auto start = Clock::now();
    const auto got = rig.fetcher->fetch(rig.cached, 0);
    BOOST_REQUIRE(!got.has_value());
    BOOST_TEST(got.error() == FetchError::timed_out);
    BOOST_TEST((Clock::now() - start < std::chrono::seconds{2}));
}

BOOST_AUTO_TEST_CASE(concurrent_demands_share_one_fetch,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{1};
    rig.store.delay = std::chrono::milliseconds{50};
    std::atomic<int> ok{0};
    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i) {
        readers.emplace_back([&] {
            if (rig.fetcher->fetch(rig.cached, 0)) {
                ++ok;
            }
        });
    }
    for (auto& t : readers) {
        t.join();
    }
    BOOST_TEST(ok.load() == 4);
    BOOST_TEST(rig.store.ranges() == 1U);
    BOOST_TEST(rig.fetcher->counters().joined == 3U);
}

BOOST_AUTO_TEST_CASE(async_demands_join_and_report_once,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{3, 0, {2}};
    rig.store.delay = std::chrono::milliseconds{20};
    std::mutex m;
    std::vector<blk::FetchResult> results;
    auto record = [&](blk::FetchResult r) {
        const std::scoped_lock lock{m};
        results.push_back(std::move(r));
    };
    rig.fetcher->fetch_async(rig.cached, 0, record);
    rig.fetcher->fetch_async(rig.cached, 0, record);            // joins the first
    BOOST_TEST(rig.fetcher->fetch(rig.cached, 0).has_value());  // and so does this
    rig.fetcher->drain();
    {
        const std::scoped_lock lock{m};
        BOOST_REQUIRE(results.size() == 2U);
        BOOST_TEST(results[0].has_value());
        BOOST_TEST((results[0] == results[1]));  // the same bytes
    }
    BOOST_TEST(rig.store.ranges() == 1U);
    // A hole fails at once, on this thread.
    rig.fetcher->fetch_async(rig.cached, 2, record);
    const std::scoped_lock lock{m};
    BOOST_REQUIRE(results.size() == 3U);
    BOOST_TEST(results[2].error() == FetchError::not_found);
}

BOOST_AUTO_TEST_CASE(shutting_down_fails_queued_async_demands,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto config = fast_config();
    config.workers = 1;
    Rig rig{3, 0, {}, nullptr, 64 * chunk_bytes, config};
    rig.store.delay = std::chrono::milliseconds{50};
    std::atomic<int> ok{0};
    std::atomic<int> shut{0};
    auto record = [&](const blk::FetchResult& r) {
        if (r) {
            ++ok;
        } else if (r.error() == FetchError::shut_down) {
            ++shut;
        }
    };
    rig.fetcher->fetch_async(rig.cached, 0, record);
    std::this_thread::sleep_for(std::chrono::milliseconds{10});  // chunk 0 starts
    rig.fetcher->fetch_async(rig.cached, 1, record);             // queued behind it
    rig.fetcher.reset();
    BOOST_TEST(ok.load() + shut.load() == 2);
    BOOST_TEST(shut.load() >= 1);
}

BOOST_AUTO_TEST_CASE(prefetches_in_the_background,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto config = fast_config();
    config.max_queued_prefetch = 2;
    config.workers = 1;
    Rig rig{8, 0, {}, nullptr, 64 * chunk_bytes, config};
    rig.store.delay = std::chrono::milliseconds{20};
    for (std::uint32_t c = 0; c < 6; ++c) {
        rig.fetcher->prefetch(rig.cached, c);
    }
    // A demand for a queued chunk joins it rather than fetching twice.
    BOOST_TEST(rig.fetcher->fetch(rig.cached, 1).has_value());
    rig.fetcher->drain();
    const auto n = rig.fetcher->counters();
    BOOST_TEST(n.prefetch_dropped > 0U);
    BOOST_TEST(rig.store.gets_at(chunk_bytes) == 1U);
    BOOST_TEST(rig.cached->resident(0));
    BOOST_TEST(rig.cached->resident(1));
    // Resident chunks are not fetched again.
    const auto before = rig.store.ranges();
    rig.fetcher->prefetch(rig.cached, 0);
    rig.fetcher->drain();
    BOOST_TEST(rig.store.ranges() == before);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(overlay)

BOOST_AUTO_TEST_CASE(keeps_writes_until_discard, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    auto o = blk::Overlay::create(dir.path(), 16 * 512, 512, 4 * 512);
    BOOST_REQUIRE(o.has_value());
    auto& ov = **o;
    // Nothing visible in the directory: the file was never linked.
    BOOST_TEST(std::filesystem::is_empty(dir.path()));
    std::vector<std::byte> data(1024, std::byte{0x5A});
    BOOST_TEST(ov.write(1024, data).has_value());
    BOOST_TEST(!ov.written(1));
    BOOST_TEST(ov.written(2));
    BOOST_TEST(ov.written(3));
    BOOST_TEST(ov.written_blocks() == 2U);
    std::vector<std::byte> out(1024);
    BOOST_TEST(ov.read(1024, out).has_value());
    BOOST_TEST((out == data));
    // Rewriting a block costs nothing against the limit; new blocks do.
    BOOST_TEST(ov.write(1024, data).has_value());
    BOOST_TEST(ov.write(4096, data).has_value());
    BOOST_TEST(ov.written_blocks() == 4U);
    BOOST_TEST(ov.write(0, std::span{data}.first(512)).error() == blk::OverlayError::full);
    BOOST_TEST(!ov.written(0));
    BOOST_TEST(ov.write(100, data).error() == blk::OverlayError::out_of_range);
    BOOST_TEST(ov.write(16 * 512, std::span{data}.first(512)).error() ==
               blk::OverlayError::out_of_range);
    ov.discard();
    BOOST_TEST(ov.written_blocks() == 0U);
    BOOST_TEST(!ov.written(2));
    BOOST_TEST(ov.write(0, std::span{data}.first(512)).has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(lazy_image_backend)

BOOST_AUTO_TEST_CASE(serves_the_image_under_the_attachment_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{4, 8192};
    const std::uint64_t image = rig.image.plain.size();
    const std::uint64_t capacity = image + (8 * 512);
    auto b = rig.backend(capacity);
    const auto key = make_key(1);
    BOOST_TEST(b->size_bytes() == capacity);
    std::vector<std::byte> out(4096);
    BOOST_TEST(b->read(0, out).error() == blk::BackendError::io);  // no key yet
    BOOST_REQUIRE(b->load_keys(key, std::nullopt).has_value());
    BOOST_TEST(b->load_keys(key, std::nullopt).error() == blk::ImageKeyError::occupied);

    // A read inside chunk 1 fetches chunk 1 only.
    const std::uint64_t at = chunk_bytes + 512;
    BOOST_REQUIRE(b->read(at, out).has_value());
    BOOST_TEST((out != slice(rig.image.plain, at, out.size())));  // ciphertext, not image bytes
    BOOST_TEST((guest_view(out, at, key) == slice(rig.image.plain, at, out.size())));
    BOOST_TEST(rig.store.ranges() == 1U);
    BOOST_TEST(rig.store.gets_at(chunk_bytes) == 1U);
    // Again: a cache hit.
    BOOST_REQUIRE(b->read(at, out).has_value());
    BOOST_TEST(rig.store.ranges() == 1U);
    BOOST_TEST(b->counters().cache_hits == 1U);

    // Across the end of the image: image bytes, then zeros.
    std::vector<std::byte> tail(8192);
    const std::uint64_t t = image - 4096;
    BOOST_REQUIRE(b->read(t, tail).has_value());
    auto expect = slice(rig.image.plain, t, 4096);
    expect.resize(8192, std::byte{0});
    BOOST_TEST((guest_view(tail, t, key) == expect));
    BOOST_TEST(b->counters().zero_reads == 8U);

    // Bounds.
    BOOST_TEST(b->read(capacity, std::span{out}.first(512)).error() ==
               blk::BackendError::out_of_range);
    BOOST_TEST(b->read(100, std::span{out}.first(512)).error() == blk::BackendError::out_of_range);
}

BOOST_AUTO_TEST_CASE(holes_read_as_zeros_without_a_fetch,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{3, 0, {1}};
    auto b = rig.backend(rig.image.plain.size());
    const auto key = make_key(2);
    BOOST_REQUIRE(b->load_keys(key, std::nullopt).has_value());
    // Spans the end of chunk 0, the hole, and the start of chunk 2.
    std::vector<std::byte> out(chunk_bytes + 1024);
    const std::uint64_t at = chunk_bytes - 512;
    BOOST_REQUIRE(b->read(at, out).has_value());
    BOOST_TEST((guest_view(out, at, key) == slice(rig.image.plain, at, out.size())));
    BOOST_TEST(rig.store.gets_at(0) == 1U);
    BOOST_TEST(rig.store.gets_at(chunk_bytes) == 0U);
    BOOST_TEST(rig.store.gets_at(2 * chunk_bytes) == 1U);
}

BOOST_AUTO_TEST_CASE(writes_stay_in_the_overlay_until_the_key_goes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    auto b = rig.backend(rig.image.plain.size());
    const auto key = make_key(3);
    BOOST_REQUIRE(b->load_keys(key, std::nullopt).has_value());
    // The function hands the backend ciphertext under K_eph.
    std::vector<std::byte> mine(1024, std::byte{0xC3});
    const std::uint64_t at = 2048;
    BOOST_REQUIRE(b->write(at, encrypt_for(mine, at, key)).has_value());
    BOOST_TEST(b->overlay().written_blocks() == 2U);
    BOOST_TEST(rig.store.ranges() == 0U);  // a write never fetches

    // Read across overlay and image blocks.
    std::vector<std::byte> out(4096);
    BOOST_REQUIRE(b->read(1024, out).has_value());
    auto expect = slice(rig.image.plain, 1024, 4096);
    std::ranges::copy(mine, expect.begin() + 1024);
    BOOST_TEST((guest_view(out, 1024, key) == expect));
    BOOST_TEST(b->counters().overlay_reads == 2U);
    BOOST_TEST(b->counters().image_reads == 6U);
    BOOST_TEST(b->flush().has_value());

    // A new attachment key sees the image again, never the old writes.
    b->drop_keys();
    BOOST_TEST(!b->holds_keys());
    BOOST_TEST(b->overlay().written_blocks() == 0U);
    BOOST_TEST(b->write(at, mine).error() == blk::BackendError::io);
    const auto key2 = make_key(4);
    BOOST_REQUIRE(b->load_keys(key2, std::nullopt).has_value());
    BOOST_REQUIRE(b->read(1024, out).has_value());
    BOOST_TEST((guest_view(out, 1024, key2) == slice(rig.image.plain, 1024, 4096)));
}

BOOST_AUTO_TEST_CASE(overlay_limit_fails_writes, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{1};
    auto b = rig.backend(rig.image.plain.size(), 1024);
    BOOST_REQUIRE(b->load_keys(make_key(5), std::nullopt).has_value());
    std::vector<std::byte> data(1024);
    BOOST_TEST(b->write(0, data).has_value());
    BOOST_TEST(b->write(1024, std::span{data}.first(512)).error() == blk::BackendError::io);
    BOOST_TEST(b->counters().overlay_full == 1U);
}

BOOST_AUTO_TEST_CASE(encrypted_images_need_their_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto image_key = make_key(9);
    Rig rig{2, 0, {}, &image_key};
    auto b = rig.backend(rig.image.plain.size());
    const auto key = make_key(6);
    BOOST_TEST(b->load_keys(key, std::nullopt).error() == blk::ImageKeyError::missing_image_key);
    BOOST_REQUIRE(b->load_keys(key, image_key).has_value());
    std::vector<std::byte> out(8192);
    const std::uint64_t at = chunk_bytes - 4096;
    BOOST_REQUIRE(b->read(at, out).has_value());
    BOOST_TEST((guest_view(out, at, key) == slice(rig.image.plain, at, out.size())));
    // The cache holds what the store holds: ciphertext under K_img.
    std::vector<std::byte> cached(512);
    BOOST_TEST(rig.cached->read(0, chunk_bytes - 4096, cached));
    BOOST_TEST((cached == slice(rig.image.stored, chunk_bytes - 4096, 512)));
    BOOST_TEST((cached != slice(rig.image.plain, chunk_bytes - 4096, 512)));

    Rig plain{1};
    auto p = plain.backend(plain.image.plain.size());
    BOOST_TEST(p->load_keys(key, image_key).error() == blk::ImageKeyError::unexpected_image_key);
    auto weak = key;
    std::copy_n(weak.begin(), half_key, weak.begin() + half_key);
    BOOST_TEST(p->load_keys(weak, std::nullopt).error() == blk::ImageKeyError::rejected);
}

BOOST_AUTO_TEST_CASE(refuses_bad_parameters, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    const std::uint64_t size = rig.image.plain.size();
    auto with = [&](std::uint64_t capacity, std::uint32_t lbs) {
        return blk::LazyImageBackend::create({.image = rig.cached,
                                              .fetcher = rig.fetcher.get(),
                                              .overlay_dir = rig.dir.path(),
                                              .capacity_bytes = capacity,
                                              .logical_block_size = lbs});
    };
    BOOST_TEST(with(size - 512, 512).error() == blk::LazyImageError::bad_capacity);
    BOOST_TEST(with(size + 100, 512).error() == blk::LazyImageError::bad_capacity);
    BOOST_TEST(with(size, 1024).error() == blk::LazyImageError::bad_block_size);
    BOOST_TEST(with(size, 4096).has_value());
    BOOST_TEST(blk::LazyImageBackend::create({.image = nullptr,
                                              .fetcher = rig.fetcher.get(),
                                              .overlay_dir = rig.dir.path(),
                                              .capacity_bytes = size})
                   .error() == blk::LazyImageError::no_image);
    auto bad_dir = blk::LazyImageBackend::create({.image = rig.cached,
                                                  .fetcher = rig.fetcher.get(),
                                                  .overlay_dir = rig.dir.path() / "missing",
                                                  .capacity_bytes = size});
    BOOST_TEST(bad_dir.error() == blk::LazyImageError::overlay);
}

BOOST_AUTO_TEST_CASE(fetch_failures_fail_the_read,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    auto b = rig.backend(rig.image.plain.size());
    BOOST_REQUIRE(b->load_keys(make_key(7), std::nullopt).has_value());
    rig.store.fail_next = 1;
    rig.store.fail_with = FetchError::not_found;
    std::vector<std::byte> out(512);
    BOOST_TEST(b->read(0, out).error() == blk::BackendError::io);
    BOOST_TEST(b->counters().fetch_failures == 1U);
    BOOST_TEST(b->read(0, out).has_value());  // a later read retries
}

BOOST_AUTO_TEST_CASE(sequential_reads_fetch_ahead,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{16, 0, {5}};
    auto b = rig.backend(rig.image.plain.size(), 0, 4);
    BOOST_REQUIRE(b->load_keys(make_key(8), std::nullopt).has_value());
    std::vector<std::byte> out(chunk_bytes);
    // First read: no history, no readahead.
    BOOST_REQUIRE(b->read(0, out).has_value());
    rig.fetcher->drain();
    BOOST_TEST(b->counters().readahead == 0U);
    // Sequential: window 1 (chunk 2), then 2 (chunks 3, 4), then 4 (6..7,
    // 8, 9 skipping the hole at 5 and anything resident).
    BOOST_REQUIRE(b->read(chunk_bytes, out).has_value());
    rig.fetcher->drain();
    BOOST_TEST(rig.cached->resident(2));
    BOOST_REQUIRE(b->read(2 * chunk_bytes, out).has_value());
    rig.fetcher->drain();
    BOOST_TEST(rig.cached->resident(3));
    BOOST_TEST(rig.cached->resident(4));
    BOOST_REQUIRE(b->read(3 * chunk_bytes, out).has_value());
    rig.fetcher->drain();
    BOOST_TEST(rig.cached->resident(6));
    BOOST_TEST(rig.cached->resident(7));
    BOOST_TEST(!rig.cached->resident(8));
    BOOST_TEST(rig.store.gets_at(5 * chunk_bytes) == 0U);
    const auto demand = b->counters().fetches;
    BOOST_TEST(demand == 2U);  // chunks 0 and 1; the rest came ahead
    // A jump resets the window.
    BOOST_REQUIRE(b->read(12 * chunk_bytes, out).has_value());
    rig.fetcher->drain();
    BOOST_TEST(!rig.cached->resident(13));
}

BOOST_AUTO_TEST_CASE(through_the_virtio_blk_function,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    const std::uint64_t capacity = rig.image.plain.size();
    auto backend = rig.backend(capacity);
    auto* lazy = backend.get();
    const auto key = make_key(10);
    ak::test::GuestRam ram;
    ak::test::RecordingInterrupts irq;
    auto fn = blk::VirtioBlkFunction::create({.geometry = {.capacity_sectors = capacity / 512,
                                                           .logical_block_size = 512,
                                                           .seg_max = 4,
                                                           .max_transfer_bytes = 16384},
                                              .num_queues = 1,
                                              .queue_size = ak::test::test_queue_size,
                                              .budget = ak::test::test_queue_size,
                                              .serial = "img"},
                                             ram.memory(), irq, std::move(backend));
    BOOST_REQUIRE(fn.has_value());
    BOOST_REQUIRE((*fn)->deliver_key(key).has_value());
    BOOST_REQUIRE(lazy->load_keys(key, std::nullopt).has_value());
    ak::test::VirtioDriver driver{ram, (*fn)->pci()};
    BOOST_REQUIRE(driver.bring_up(vio::feature_bit(vio::feature_version_1), {0}));

    auto io = [&](bool write, std::uint64_t sector, std::span<const std::byte> data,
                  std::size_t len) -> std::vector<std::byte> {
        std::vector<vio::Gpa> gpas;
        driver.post(0,
                    {{.len = 16, .writable = false},
                     {.len = static_cast<std::uint32_t>(len), .writable = !write},
                     {.len = 1, .writable = true}},
                    &gpas);
        std::vector<std::byte> hdr;
        ak::wire::Writer w{hdr};
        w.le32(write ? 1 : 0);
        w.le32(0);
        w.le64(sector);
        ram.put_bytes(gpas[0], hdr);
        if (write) {
            ram.put_bytes(gpas[1], data);
        }
        ram.put<std::byte>(gpas[2], std::byte{0xFF});
        BOOST_REQUIRE(driver.notify(0));
        // A read that misses parks until the fetch lands.
        run_loop((*fn)->wake_fd(), [&] { return (*fn)->poll(); },
                 [&] { return (*fn)->in_flight() == 0; });
        BOOST_TEST(ram.get<std::byte>(gpas[2]) == std::byte{0});
        return ram.bytes(gpas[1], len);
    };

    // The guest reads the image as plaintext.
    BOOST_TEST((io(false, 130, {}, 4096) == slice(rig.image.plain, 130 * 512, 4096)));
    // Writes read back; the overlay holds only ciphertext.
    std::vector<std::byte> mine(2048, std::byte{0x42});
    static_cast<void>(io(true, 8, mine, mine.size()));
    BOOST_TEST((io(false, 8, {}, mine.size()) == mine));
    std::vector<std::byte> raw(2048);
    // The overlay's file is the backend's; its stored bytes are not `mine`.
    BOOST_TEST(lazy->overlay().read(8 * 512, raw).has_value());
    BOOST_TEST((raw != mine));
    BOOST_TEST(lazy->counters().parked == 1U);  // the first read's miss
}

BOOST_AUTO_TEST_CASE(submitted_misses_park_until_the_fetch_lands,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{3, 0, {1}};
    auto b = rig.backend(rig.image.plain.size());
    const auto key = make_key(11);
    BOOST_REQUIRE(b->load_keys(key, std::nullopt).has_value());
    rig.store.delay = std::chrono::milliseconds{20};
    // Spans chunk 0, the hole and chunk 2: two fetches, one read.
    std::vector<std::byte> out(chunk_bytes + 1024);
    const std::uint64_t at = chunk_bytes - 512;
    Outcome o;
    b->submit_read(at, out, o.completion());
    BOOST_TEST(!o.ran);
    BOOST_TEST(b->parked() == 1U);
    BOOST_TEST(b->counters().fetches == 2U);
    settle(*b);
    BOOST_REQUIRE(o.ran);
    BOOST_REQUIRE(o.result.has_value());
    BOOST_TEST((guest_view(out, at, key) == slice(rig.image.plain, at, out.size())));
    BOOST_TEST(rig.store.ranges() == 2U);
    BOOST_TEST(!b->poll());  // nothing left

    // Resident now: the next submit completes inside the call.
    Outcome again;
    b->submit_read(at, out, again.completion());
    BOOST_TEST(again.ran);
    BOOST_TEST(again.result.has_value());
    BOOST_TEST(b->counters().parked == 1U);
    BOOST_TEST(rig.store.ranges() == 2U);
}

BOOST_AUTO_TEST_CASE(fetched_chunks_serve_the_read_without_cache_room,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // The cache holds one chunk; the read needs two.
    Rig rig{2, 0, {}, nullptr, chunk_bytes};
    auto b = rig.backend(rig.image.plain.size());
    const auto key = make_key(12);
    BOOST_REQUIRE(b->load_keys(key, std::nullopt).has_value());
    std::vector<std::byte> out(2 * chunk_bytes);
    Outcome o;
    b->submit_read(0, out, o.completion());
    settle(*b);
    BOOST_REQUIRE(o.ran);
    BOOST_REQUIRE(o.result.has_value());
    BOOST_TEST((guest_view(out, 0, key) == rig.image.plain));
    BOOST_TEST(rig.store.ranges() == 2U);  // no synchronous second fetch
}

BOOST_AUTO_TEST_CASE(a_failed_fetch_fails_the_parked_read,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    auto b = rig.backend(rig.image.plain.size());
    BOOST_REQUIRE(b->load_keys(make_key(13), std::nullopt).has_value());
    rig.store.fail_next = 1;
    rig.store.fail_with = FetchError::not_found;
    std::vector<std::byte> out(512);
    Outcome o;
    b->submit_read(0, out, o.completion());
    settle(*b);
    BOOST_REQUIRE(o.ran);
    BOOST_TEST(o.result.error() == blk::BackendError::io);
    BOOST_TEST(b->counters().fetch_failures == 1U);
    // Bad requests and missing keys still fail inside the call.
    Outcome bad;
    b->submit_read(100, out, bad.completion());
    BOOST_TEST(bad.ran);
    BOOST_TEST(bad.result.error() == blk::BackendError::out_of_range);
}

BOOST_AUTO_TEST_CASE(dropping_the_keys_fails_a_parked_read,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    auto b = rig.backend(rig.image.plain.size());
    BOOST_REQUIRE(b->load_keys(make_key(14), std::nullopt).has_value());
    rig.store.delay = std::chrono::milliseconds{20};
    std::vector<std::byte> out(512);
    Outcome o;
    b->submit_read(0, out, o.completion());
    BOOST_TEST(!o.ran);
    b->drop_keys();
    settle(*b);
    BOOST_REQUIRE(o.ran);
    BOOST_TEST(o.result.error() == blk::BackendError::io);
}

BOOST_AUTO_TEST_CASE(destroying_the_backend_drops_parked_reads,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig rig{2};
    auto b = rig.backend(rig.image.plain.size());
    BOOST_REQUIRE(b->load_keys(make_key(15), std::nullopt).has_value());
    rig.store.delay = std::chrono::milliseconds{20};
    std::vector<std::byte> out(512);
    Outcome o;
    b->submit_read(0, out, o.completion());
    b.reset();
    rig.fetcher->drain();  // the fetch lands in an inbox nobody reads
    BOOST_TEST(!o.ran);
    BOOST_TEST(rig.cached->resident(0));
}

BOOST_AUTO_TEST_SUITE_END()
