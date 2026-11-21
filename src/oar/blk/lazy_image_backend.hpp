// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The BlockBackend of an image volume (.kiro/specs/oar-blk-data-plane/
// Requirement 8, design "Image volumes"): an image in object storage,
// read-only and fetched lazily, under one attachment's ephemeral overlay.
//
// VirtioBlkFunction above it is unchanged: it encrypts every write and
// decrypts every read with the attachment's key K_eph, so this backend
// receives and must return ciphertext under K_eph. Per logical block:
//
//   written by the guest  the overlay's bytes, already under K_eph;
//   in the image          the image's bytes from the chunk cache, or fetched
//                         on a miss (holes are zeros), decrypted with the
//                         image key K_img when the image is encrypted, then
//                         encrypted with K_eph at the same block number;
//   past the image        zeros, encrypted with K_eph.
//
// Image plaintext exists only transiently in the caller's buffer (the
// function's bounce buffer, which it wipes), in the process that decrypts
// for the guest anyway.
//
// load_keys() builds the K_eph cipher (and K_img's for an encrypted image);
// the OpenSSL contexts are the only copies and are cleansed when freed.
// drop_keys() frees them and discards the overlay, so no later key can read
// an earlier attachment's writes (Requirement 8.7). Without keys, reads and
// writes fail.
//
// Sequential reads drive readahead: a read starting where the last one
// ended, or in the next chunk, doubles a window of chunks to prefetch, up
// to max_readahead_chunks; any other read resets it.
//
// Misses (Requirement 8.10). With a Waker, read_ready() is how a read
// avoids waiting: it answers false while a chunk the range needs is
// neither cached nor here, after starting an asynchronous demand fetch for
// it, and the fetcher's callback queues the result and signals the waker.
// The function parks the request meanwhile and serves it once read_ready()
// says yes; the role thread never waits on the store. Arrived chunks are
// also kept here (the most recent few), so a read that follows finds them
// even if the cache had no room; a failed fetch is remembered until the
// read that waited for it fails with it. Without a waker, or for a read
// that comes without asking, a miss blocks the caller until the fetcher
// has the chunk or gives up at its deadline.
//
// Not thread-safe: the role thread owns it.

#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include "oar/blk/chunk_cache.hpp"
#include "oar/blk/fetcher.hpp"
#include "oar/blk/overlay.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "oar/blk/waker.hpp"
#include "oar/blk/xts_cipher.hpp"

namespace ak::oar::blk {

struct LazyImageParams {
    std::shared_ptr<CachedImage> image;
    Fetcher* fetcher{nullptr};  // must outlive the backend
    std::filesystem::path overlay_dir;
    // At least the image size, whole logical blocks; more reads as zeros.
    std::uint64_t capacity_bytes{0};
    // The volume's block size (the XTS data unit): the image's for an
    // encrypted image; any block size that divides the image otherwise.
    std::uint32_t logical_block_size{512};
    std::uint64_t overlay_limit_bytes{0};  // 0: up to the capacity
    std::uint32_t max_readahead_chunks{8};
    // Signalled when an asynchronous fetch finishes; none: misses block.
    std::shared_ptr<Waker> waker;
};

enum class LazyImageError : std::uint8_t {
    no_image,        // no image or no fetcher
    bad_block_size,  // not 512/4096, or does not fit the image
    bad_capacity,    // smaller than the image, or not whole blocks
    overlay,         // the overlay file could not be created
};

enum class ImageKeyError : std::uint8_t {
    occupied,              // keys are already loaded: drop_keys first
    rejected,              // XtsCipher refused a key (equal halves)
    missing_image_key,     // the image is encrypted and no K_img came
    unexpected_image_key,  // the image is plaintext and a K_img came
};

[[nodiscard]] auto to_string(LazyImageError e) noexcept -> const char*;
[[nodiscard]] auto to_string(ImageKeyError e) noexcept -> const char*;

struct LazyImageCounters {
    std::uint64_t overlay_reads{0};  // blocks served from the overlay
    std::uint64_t image_reads{0};    // blocks served from the image (cache, fetch or hole)
    std::uint64_t zero_reads{0};     // blocks past the end of the image
    std::uint64_t cache_hits{0};     // chunk pieces found in the cache
    std::uint64_t fetches{0};        // demand fetches that blocked the caller
    std::uint64_t async_fetches{0};  // demand fetches started by read_ready()
    std::uint64_t arrived_hits{0};   // chunk pieces served from the arrived chunks
    std::uint64_t fetch_failures{0};
    std::uint64_t readahead{0};  // chunks handed to prefetch
    std::uint64_t writes{0};
    std::uint64_t overlay_full{0};
};

class LazyImageBackend final : public BlockBackend {
public:
    [[nodiscard]] static auto create(LazyImageParams params)
        -> std::expected<std::unique_ptr<LazyImageBackend>, LazyImageError>;

    LazyImageBackend(const LazyImageBackend&) = delete;
    auto operator=(const LazyImageBackend&) -> LazyImageBackend& = delete;
    LazyImageBackend(LazyImageBackend&&) = delete;
    auto operator=(LazyImageBackend&&) -> LazyImageBackend& = delete;
    ~LazyImageBackend() override = default;

    [[nodiscard]] auto load_keys(XtsKey ephemeral, std::optional<XtsKey> image_key)
        -> std::expected<void, ImageKeyError>;
    auto drop_keys() noexcept -> void;
    [[nodiscard]] auto holds_keys() const noexcept -> bool { return _eph.has_value(); }

    [[nodiscard]] auto image() const noexcept -> const CachedImage& { return *_params.image; }
    [[nodiscard]] auto overlay() const noexcept -> const Overlay& { return *_overlay; }
    [[nodiscard]] auto counters() const noexcept -> const LazyImageCounters& { return _counters; }

    // BlockBackend
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override {
        return _params.capacity_bytes;
    }
    [[nodiscard]] auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, BackendError> override;
    [[nodiscard]] auto write(std::uint64_t offset, std::span<const std::byte> in)
        -> std::expected<void, BackendError> override;
    [[nodiscard]] auto read_ready(std::uint64_t offset, std::size_t len) -> bool override;
    // The overlay does not outlive the attachment: nothing to make durable.
    [[nodiscard]] auto flush() -> std::expected<void, BackendError> override { return {}; }

private:
    enum class Source : std::uint8_t {
        overlay,
        image,
        zero,
    };

    // Results of asynchronous fetches, handed from fetcher workers to the
    // role thread. Shared with the callbacks, so a fetch that finishes
    // after the backend is gone has somewhere harmless to land.
    struct Inbox {
        std::mutex mutex;
        std::vector<std::pair<std::uint32_t, FetchResult>> results;
        std::shared_ptr<Waker> waker;
    };

    // Arrived chunks kept beyond the cache.
    static constexpr std::size_t max_arrived = 16;

    LazyImageBackend(LazyImageParams params, std::unique_ptr<Overlay> overlay)
        : _params{std::move(params)},
          _overlay{std::move(overlay)},
          _inbox{std::make_shared<Inbox>()} {
        _inbox->waker = _params.waker;
    }

    [[nodiscard]] auto source(std::uint64_t block) const noexcept -> Source;
    [[nodiscard]] auto check(std::uint64_t offset, std::size_t len) const noexcept -> bool;
    // Image bytes [offset, offset + out.size()) as plaintext.
    [[nodiscard]] auto read_image(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, BackendError>;
    auto readahead(std::uint64_t offset, std::uint64_t end) -> void;
    // Moves finished asynchronous fetches out of the inbox.
    auto collect() -> void;
    // Whether the chunk's bytes can be had without waiting; if not, makes
    // sure an asynchronous fetch for it is under way.
    auto chunk_ready(std::uint32_t chunk) -> bool;

    LazyImageParams _params;
    std::unique_ptr<Overlay> _overlay;
    std::optional<XtsCipher> _eph;
    std::optional<XtsCipher> _img;
    std::optional<std::uint64_t> _last_end;  // end of the previous read
    std::uint32_t _window{0};
    std::shared_ptr<Inbox> _inbox;
    std::set<std::uint32_t> _awaited;                           // asynchronous fetches under way
    std::deque<std::pair<std::uint32_t, ChunkBytes>> _arrived;  // newest last
    std::map<std::uint32_t, FetchError> _failed;
    LazyImageCounters _counters;
};

}  // namespace ak::oar::blk
