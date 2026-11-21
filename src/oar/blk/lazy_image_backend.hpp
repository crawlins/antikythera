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
// read() is synchronous: a miss blocks the caller until the fetcher has
// the chunk or gives up at its deadline (Requirement 8.10). submit_read()
// is not (block-volume-service task 3, which subsumes oar-blk task 14): a
// read whose image chunks are all resident or holes completes at once;
// otherwise it parks, each missing chunk goes to Fetcher::fetch_async, and
// the arrivals land in an inbox whose eventfd is wake_fd(). poll() takes
// them on the role thread and completes each read once its last chunk is
// in (or one failed, which fails the read with io). The fetched bytes are
// used even if the cache had no room for them; a chunk that was resident
// at submit and evicted before completion is fetched again synchronously.
// The completion decrypts and re-encrypts with whatever keys are loaded
// then: none fails the read, as after drop_keys(). Destroying the backend
// drops parked reads without running their completions; fetches still in
// flight post to the inbox, which they keep alive, and nobody reads it.
//
// Not thread-safe: the role thread owns it (the inbox is the only state
// another thread touches).

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

#include "oar/blk/chunk_cache.hpp"
#include "oar/blk/fetcher.hpp"
#include "oar/blk/overlay.hpp"
#include "oar/blk/virtio_blk_function.hpp"
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
};

enum class LazyImageError : std::uint8_t {
    no_image,        // no image or no fetcher
    bad_block_size,  // not 512/4096, or does not fit the image
    bad_capacity,    // smaller than the image, or not whole blocks
    overlay,         // the overlay file could not be created
    wake,            // the inbox's eventfd could not be created
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
    std::uint64_t fetches{0};        // demand fetches
    std::uint64_t parked{0};         // reads that waited for fetch_async
    std::uint64_t fetch_failures{0};
    std::uint64_t readahead{0};  // chunks handed to prefetch
    std::uint64_t writes{0};
    std::uint64_t overlay_full{0};
};

class LazyImageBackend final : public SyncBlockBackend {
public:
    [[nodiscard]] static auto create(LazyImageParams params)
        -> std::expected<std::unique_ptr<LazyImageBackend>, LazyImageError>;

    LazyImageBackend(const LazyImageBackend&) = delete;
    auto operator=(const LazyImageBackend&) -> LazyImageBackend& = delete;
    LazyImageBackend(LazyImageBackend&&) = delete;
    auto operator=(LazyImageBackend&&) -> LazyImageBackend& = delete;
    ~LazyImageBackend() override;

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
    // The overlay does not outlive the attachment: nothing to make durable.
    [[nodiscard]] auto flush() -> std::expected<void, BackendError> override { return {}; }
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, BackendCompletion done)
        -> void override;
    [[nodiscard]] auto poll() -> bool override;
    [[nodiscard]] auto wake_fd() const noexcept -> int override { return _inbox->fd; }
    // Reads waiting for fetches.
    [[nodiscard]] auto parked() const noexcept -> std::size_t { return _reads.size(); }

private:
    enum class Source : std::uint8_t {
        overlay,
        image,
        zero,
    };

    using Fetched = std::map<std::uint32_t, ChunkBytes>;

    struct Arrival {
        std::uint64_t read{0};
        std::uint32_t chunk{0};
        FetchResult result;
    };
    // Where fetcher workers leave arrivals for the role thread. Shared with
    // the callbacks so a fetch finishing after the backend is gone is safe.
    struct Inbox {
        Inbox(const Inbox&) = delete;
        auto operator=(const Inbox&) -> Inbox& = delete;
        Inbox(Inbox&&) = delete;
        auto operator=(Inbox&&) -> Inbox& = delete;
        explicit Inbox(int event_fd) noexcept : fd{event_fd} {}
        ~Inbox();
        auto post(Arrival a) -> void;
        [[nodiscard]] auto take() -> std::vector<Arrival>;

        const int fd;
        std::mutex mutex;
        std::vector<Arrival> arrivals;
    };
    struct ParkedRead {
        std::uint64_t offset{0};
        std::span<std::byte> out;
        BackendCompletion done;
        std::size_t waiting{0};
        bool failed{false};
        Fetched chunks;
    };

    LazyImageBackend(LazyImageParams params, std::unique_ptr<Overlay> overlay,
                     std::shared_ptr<Inbox> inbox) noexcept
        : _params{std::move(params)}, _overlay{std::move(overlay)}, _inbox{std::move(inbox)} {}

    [[nodiscard]] auto source(std::uint64_t block) const noexcept -> Source;
    [[nodiscard]] auto check(std::uint64_t offset, std::size_t len) const noexcept -> bool;
    // The checked range as ciphertext under K_eph, chunks in `fetched`
    // taking the place of the cache.
    [[nodiscard]] auto read_blocks(std::uint64_t offset, std::span<std::byte> out,
                                   const Fetched* fetched) -> std::expected<void, BackendError>;
    // Image bytes [offset, offset + out.size()) as plaintext.
    [[nodiscard]] auto read_image(std::uint64_t offset, std::span<std::byte> out,
                                  const Fetched* fetched) -> std::expected<void, BackendError>;
    // The image chunks under [offset, end) a read would have to fetch.
    [[nodiscard]] auto misses(std::uint64_t offset, std::uint64_t end) const
        -> std::vector<std::uint32_t>;
    auto readahead(std::uint64_t offset, std::uint64_t end) -> void;

    LazyImageParams _params;
    std::unique_ptr<Overlay> _overlay;
    std::optional<XtsCipher> _eph;
    std::optional<XtsCipher> _img;
    std::optional<std::uint64_t> _last_end;  // end of the previous read
    std::uint32_t _window{0};
    LazyImageCounters _counters;
    std::shared_ptr<Inbox> _inbox;
    std::map<std::uint64_t, ParkedRead> _reads;  // by id
    std::uint64_t _next_read{1};
};

}  // namespace ak::oar::blk
