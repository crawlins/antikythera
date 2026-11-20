// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Fetches image chunks from the object store (.kiro/specs/oar-blk-data-plane/
// Requirements 8.2-8.5 and 8.10, design "Fetcher"): a few worker threads
// share one ObjectStore. Every chunk is checked against its manifest digest
// before anyone sees it or it enters the cache.
//
//   fetch()     a demand fetch: blocks the caller until the chunk is here
//               (or failed) and returns its bytes, which the caller can use
//               even if the cache had no room for them. Demand fetches go
//               ahead of readahead.
//   fetch_async()  a demand fetch that does not wait: `done` is called with
//               the result on a worker thread when the chunk is here (or
//               failed). It must be quick and must not call back into the
//               fetcher; the role uses it to wake its thread (Waker).
//   prefetch()  readahead: queued behind demand fetches, dropped when the
//               queue is full or the chunk is already resident or coming.
//
// A chunk has at most one fetch in flight; every waiter shares it, and a
// demand for a chunk queued for readahead promotes it. Each fetch has one
// deadline for all its attempts; connection errors, malformed responses and
// digest mismatches are retried with jittered exponential backoff up to
// `attempts` in all; not_found, denied and timed_out are final.
//
// Holes are never fetched: the caller reads them as zeros.

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "oar/blk/chunk_cache.hpp"
#include "oar/blk/object_store.hpp"

namespace ak::oar::blk {

struct FetcherConfig {
    std::size_t workers{4};
    std::chrono::milliseconds deadline{5000};  // per chunk, all attempts
    unsigned attempts{4};                      // the first try and 3 retries
    std::chrono::milliseconds backoff{50};     // doubled per retry, plus jitter
    std::size_t max_queued_prefetch{64};
};

struct FetcherCounters {
    std::uint64_t fetched{0};  // chunks fetched and verified
    std::uint64_t fetched_bytes{0};
    std::uint64_t retries{0};
    std::uint64_t corrupt{0};  // responses that failed their digest
    std::uint64_t failed{0};   // fetches that gave up
    std::uint64_t prefetch_queued{0};
    std::uint64_t prefetch_dropped{0};  // queue full
    std::uint64_t joined{0};            // demand fetches that found one in flight
};

using ChunkBytes = std::shared_ptr<const std::vector<std::byte>>;
using FetchResult = std::expected<ChunkBytes, FetchError>;
using FetchCallback = std::function<void(const FetchResult&)>;

class Fetcher {
public:
    // `store` must outlive the fetcher. At least one worker and attempt.
    [[nodiscard]] static auto create(ObjectStore& store, FetcherConfig config)
        -> std::unique_ptr<Fetcher>;

    Fetcher(const Fetcher&) = delete;
    auto operator=(const Fetcher&) -> Fetcher& = delete;
    Fetcher(Fetcher&&) = delete;
    auto operator=(Fetcher&&) -> Fetcher& = delete;
    // Stops the workers after their current fetch; queued fetches fail
    // with shut_down.
    ~Fetcher();

    [[nodiscard]] auto fetch(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk)
        -> std::expected<ChunkBytes, FetchError>;
    // Refuses a hole or a chunk past the image (not_found) and a stopping
    // fetcher (shut_down) at once, without calling `done`; otherwise calls
    // `done` exactly once, later, from a worker or the destructor.
    [[nodiscard]] auto fetch_async(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk,
                                   FetchCallback done) -> std::expected<void, FetchError>;
    auto prefetch(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk) -> void;

    // Waits until nothing is queued or in flight (tests).
    auto drain() -> void;
    [[nodiscard]] auto counters() const -> FetcherCounters;

private:
    struct Job {
        std::shared_ptr<CachedImage> image;
        std::uint32_t chunk{0};
        bool demand{false};
        bool started{false};
        bool done{false};
        FetchResult result{std::unexpected(FetchError::shut_down)};
        std::vector<FetchCallback> callbacks;  // fetch_async waiters
    };
    using Key = std::pair<const CachedImage*, std::uint32_t>;

    Fetcher(ObjectStore& store, FetcherConfig config) : _store{&store}, _config{config} {}

    auto run() -> void;
    [[nodiscard]] auto download(const Job& job) -> FetchResult;
    // Finds or queues the demand job for a chunk; caller holds _mutex.
    auto demand(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk)
        -> std::shared_ptr<Job>;
    // Caller holds _mutex, and runs the returned callbacks (with
    // job->result) after releasing it.
    [[nodiscard]] auto finish(const std::shared_ptr<Job>& job, FetchResult result)
        -> std::vector<FetchCallback>;

    ObjectStore* _store;
    FetcherConfig _config;
    mutable std::mutex _mutex;
    std::condition_variable _work;  // workers: something queued, or stopping
    std::condition_variable _done;  // waiters: a job finished
    std::condition_variable _stop;  // retry backoff: stopping
    bool _stopping{false};
    std::deque<std::shared_ptr<Job>> _demand;
    std::deque<std::shared_ptr<Job>> _prefetch;
    std::map<Key, std::shared_ptr<Job>> _jobs;  // queued or in flight
    FetcherCounters _counters;
    std::vector<std::thread> _workers;
};

}  // namespace ak::oar::blk
