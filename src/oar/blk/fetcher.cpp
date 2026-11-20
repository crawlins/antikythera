// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/fetcher.hpp"

#include <algorithm>
#include <random>
#include <utility>
#include <vector>

namespace ak::oar::blk {

auto Fetcher::create(ObjectStore& store, FetcherConfig config) -> std::unique_ptr<Fetcher> {
    config.workers = std::max<std::size_t>(config.workers, 1);
    config.attempts = std::max(config.attempts, 1U);
    std::unique_ptr<Fetcher> f{new Fetcher(store, config)};
    f->_workers.reserve(config.workers);
    for (std::size_t i = 0; i < config.workers; ++i) {
        f->_workers.emplace_back([p = f.get()] { p->run(); });
    }
    return f;
}

Fetcher::~Fetcher() {
    {
        const std::scoped_lock lock{_mutex};
        _stopping = true;
    }
    _work.notify_all();
    _stop.notify_all();
    for (auto& t : _workers) {
        t.join();
    }
    std::vector<std::pair<std::shared_ptr<Job>, std::vector<FetchCallback>>> waiting;
    {
        const std::scoped_lock lock{_mutex};
        for (auto* q : {&_demand, &_prefetch}) {
            for (const auto& job : *q) {
                if (!job->started && !job->done) {
                    waiting.emplace_back(job, finish(job, std::unexpected(FetchError::shut_down)));
                }
            }
            q->clear();
        }
    }
    for (const auto& [job, callbacks] : waiting) {
        for (const auto& done : callbacks) {
            done(job->result);
        }
    }
}

auto Fetcher::fetch(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk)
    -> std::expected<ChunkBytes, FetchError> {
    if (chunk >= image->manifest().chunk_count() || image->manifest().is_hole(chunk)) {
        return std::unexpected(FetchError::not_found);
    }
    std::unique_lock lock{_mutex};
    if (_stopping) {
        return std::unexpected(FetchError::shut_down);
    }
    const auto job = demand(image, chunk);
    _done.wait(lock, [&] { return job->done; });
    return job->result;
}

auto Fetcher::fetch_async(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk,
                          FetchCallback done) -> std::expected<void, FetchError> {
    if (chunk >= image->manifest().chunk_count() || image->manifest().is_hole(chunk)) {
        return std::unexpected(FetchError::not_found);
    }
    const std::scoped_lock lock{_mutex};
    if (_stopping) {
        return std::unexpected(FetchError::shut_down);
    }
    demand(image, chunk)->callbacks.push_back(std::move(done));
    return {};
}

auto Fetcher::demand(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk)
    -> std::shared_ptr<Job> {
    if (auto it = _jobs.find({image.get(), chunk}); it != _jobs.end()) {
        auto job = it->second;
        ++_counters.joined;
        if (!job->started && !job->demand) {
            job->demand = true;  // promote readahead; the prefetch entry is skipped later
            _demand.push_back(job);
            _work.notify_one();
        }
        return job;
    }
    auto job = std::make_shared<Job>();
    job->image = image;
    job->chunk = chunk;
    job->demand = true;
    _jobs.emplace(Key{image.get(), chunk}, job);
    _demand.push_back(job);
    _work.notify_one();
    return job;
}

auto Fetcher::prefetch(const std::shared_ptr<CachedImage>& image, std::uint32_t chunk) -> void {
    if (chunk >= image->manifest().chunk_count() || image->manifest().is_hole(chunk) ||
        image->resident(chunk)) {
        return;
    }
    const std::scoped_lock lock{_mutex};
    if (_stopping || _jobs.contains({image.get(), chunk})) {
        return;
    }
    if (_prefetch.size() >= _config.max_queued_prefetch) {
        ++_counters.prefetch_dropped;
        return;
    }
    auto job = std::make_shared<Job>();
    job->image = image;
    job->chunk = chunk;
    _jobs.emplace(Key{image.get(), chunk}, job);
    _prefetch.push_back(job);
    ++_counters.prefetch_queued;
    _work.notify_one();
}

auto Fetcher::drain() -> void {
    std::unique_lock lock{_mutex};
    _done.wait(lock, [&] { return _jobs.empty(); });
}

auto Fetcher::counters() const -> FetcherCounters {
    const std::scoped_lock lock{_mutex};
    return _counters;
}

auto Fetcher::run() -> void {
    std::unique_lock lock{_mutex};
    while (true) {
        _work.wait(lock, [&] { return _stopping || !_demand.empty() || !_prefetch.empty(); });
        if (_stopping) {
            return;
        }
        auto& queue = _demand.empty() ? _prefetch : _demand;
        auto job = queue.front();
        queue.pop_front();
        if (job->started || job->done) {
            continue;  // a promoted job's second entry
        }
        job->started = true;
        lock.unlock();
        auto result = download(*job);
        lock.lock();
        auto callbacks = finish(job, std::move(result));
        if (!callbacks.empty()) {
            // job->result is final: done is set and nothing writes it again.
            lock.unlock();
            for (const auto& done : callbacks) {
                done(job->result);
            }
            lock.lock();
        }
    }
}

auto Fetcher::download(const Job& job) -> FetchResult {
    const ImageManifest& m = job.image->manifest();
    const auto deadline = ObjectStore::Clock::now() + _config.deadline;
    thread_local std::minstd_rand jitter{std::random_device{}()};
    auto bytes = std::make_shared<std::vector<std::byte>>(m.chunk_length(job.chunk));
    FetchError last = FetchError::io;
    for (unsigned attempt = 0; attempt < _config.attempts; ++attempt) {
        if (attempt > 0) {
            const auto base = _config.backoff * (1U << std::min(attempt - 1, 10U));
            const auto extra = std::chrono::milliseconds{
                std::uniform_int_distribution<std::int64_t>{0, base.count()}(jitter)};
            const auto wake = std::min(ObjectStore::Clock::now() + base + extra, deadline);
            std::unique_lock lock{_mutex};
            ++_counters.retries;
            if (_stop.wait_until(lock, wake, [&] { return _stopping; })) {
                return std::unexpected(FetchError::shut_down);
            }
        }
        if (ObjectStore::Clock::now() >= deadline) {
            last = FetchError::timed_out;
            break;
        }
        auto got =
            _store->get_range(job.image->data_key(), m.chunk_offset(job.chunk), *bytes, deadline);
        if (got) {
            if (chunk_matches(m, job.chunk, *bytes)) {
                job.image->insert(job.chunk, *bytes);
                return bytes;
            }
            got = std::unexpected(FetchError::corrupt);
            const std::scoped_lock lock{_mutex};
            ++_counters.corrupt;
        }
        last = got.error();
        if (!retryable(last)) {
            break;
        }
    }
    return std::unexpected(last);
}

auto Fetcher::finish(const std::shared_ptr<Job>& job, FetchResult result)
    -> std::vector<FetchCallback> {
    if (result) {
        ++_counters.fetched;
        _counters.fetched_bytes += (*result)->size();
    } else {
        ++_counters.failed;
    }
    job->result = std::move(result);
    job->done = true;
    _jobs.erase({job->image.get(), job->chunk});
    _done.notify_all();
    return std::exchange(job->callbacks, {});
}

}  // namespace ak::oar::blk
