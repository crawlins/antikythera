// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/lazy_image_backend.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace ak::oar::blk {

auto to_string(LazyImageError e) noexcept -> const char* {
    switch (e) {
        case LazyImageError::no_image:
            return "no_image";
        case LazyImageError::bad_block_size:
            return "bad_block_size";
        case LazyImageError::bad_capacity:
            return "bad_capacity";
        case LazyImageError::overlay:
            return "overlay";
    }
    return "unknown";
}

auto to_string(ImageKeyError e) noexcept -> const char* {
    switch (e) {
        case ImageKeyError::occupied:
            return "occupied";
        case ImageKeyError::rejected:
            return "rejected";
        case ImageKeyError::missing_image_key:
            return "missing_image_key";
        case ImageKeyError::unexpected_image_key:
            return "unexpected_image_key";
    }
    return "unknown";
}

auto LazyImageBackend::create(LazyImageParams params)
    -> std::expected<std::unique_ptr<LazyImageBackend>, LazyImageError> {
    if (!params.image || params.fetcher == nullptr) {
        return std::unexpected(LazyImageError::no_image);
    }
    const ImageManifest& m = params.image->manifest();
    const std::uint32_t lbs = params.logical_block_size;
    if ((lbs != data_unit_512 && lbs != data_unit_4k) || m.image_bytes % lbs != 0 ||
        (m.encrypted && lbs != m.logical_block_size)) {
        return std::unexpected(LazyImageError::bad_block_size);
    }
    if (params.capacity_bytes < m.image_bytes || params.capacity_bytes % lbs != 0) {
        return std::unexpected(LazyImageError::bad_capacity);
    }
    auto overlay =
        Overlay::create(params.overlay_dir, params.capacity_bytes, lbs, params.overlay_limit_bytes);
    if (!overlay) {
        return std::unexpected(LazyImageError::overlay);
    }
    return std::unique_ptr<LazyImageBackend>(
        new LazyImageBackend(std::move(params), std::move(*overlay)));
}

auto LazyImageBackend::load_keys(XtsKey ephemeral, std::optional<XtsKey> image_key)
    -> std::expected<void, ImageKeyError> {
    if (_eph) {
        return std::unexpected(ImageKeyError::occupied);
    }
    const ImageManifest& m = _params.image->manifest();
    if (m.encrypted && !image_key) {
        return std::unexpected(ImageKeyError::missing_image_key);
    }
    if (!m.encrypted && image_key) {
        return std::unexpected(ImageKeyError::unexpected_image_key);
    }
    auto eph = XtsCipher::create(ephemeral, _params.logical_block_size);
    if (!eph) {
        return std::unexpected(ImageKeyError::rejected);
    }
    if (image_key) {
        auto img = XtsCipher::create(*image_key, m.logical_block_size);
        if (!img) {
            return std::unexpected(ImageKeyError::rejected);
        }
        _img.emplace(std::move(*img));
    }
    _eph.emplace(std::move(*eph));
    return {};
}

auto LazyImageBackend::drop_keys() noexcept -> void {
    _eph.reset();
    _img.reset();
    _overlay->discard();
    _failed.clear();
    _last_end.reset();
    _window = 0;
}

auto LazyImageBackend::source(std::uint64_t block) const noexcept -> Source {
    if (_overlay->written(block)) {
        return Source::overlay;
    }
    return block * _params.logical_block_size < _params.image->manifest().image_bytes
               ? Source::image
               : Source::zero;
}

auto LazyImageBackend::check(std::uint64_t offset, std::size_t len) const noexcept -> bool {
    const std::uint32_t lbs = _params.logical_block_size;
    return len != 0 && offset % lbs == 0 && len % lbs == 0 && offset <= _params.capacity_bytes &&
           len <= _params.capacity_bytes - offset;
}

auto LazyImageBackend::read(std::uint64_t offset, std::span<std::byte> out)
    -> std::expected<void, BackendError> {
    if (!check(offset, out.size())) {
        return std::unexpected(BackendError::out_of_range);
    }
    if (!_eph) {
        return std::unexpected(BackendError::io);
    }
    const std::uint32_t lbs = _params.logical_block_size;
    std::size_t pos = 0;
    while (pos < out.size()) {
        const std::uint64_t first = (offset + pos) / lbs;
        const Source kind = source(first);
        std::size_t len = lbs;
        while (pos + len < out.size() && source(first + (len / lbs)) == kind) {
            len += lbs;
        }
        const auto run = out.subspan(pos, len);
        const std::uint64_t blocks = len / lbs;
        switch (kind) {
            case Source::overlay:
                if (!_overlay->read(offset + pos, run)) {
                    return std::unexpected(BackendError::io);
                }
                _counters.overlay_reads += blocks;
                break;
            case Source::image:
                if (auto r = read_image(offset + pos, run); !r) {
                    return r;
                }
                _counters.image_reads += blocks;
                break;
            case Source::zero:
                std::ranges::fill(run, std::byte{0});
                _counters.zero_reads += blocks;
                break;
        }
        if (kind != Source::overlay && !_eph->encrypt(first, run, run)) {
            return std::unexpected(BackendError::io);
        }
        pos += len;
    }
    readahead(offset, offset + out.size());
    return {};
}

auto LazyImageBackend::write(std::uint64_t offset, std::span<const std::byte> in)
    -> std::expected<void, BackendError> {
    if (!check(offset, in.size())) {
        return std::unexpected(BackendError::out_of_range);
    }
    if (!_eph) {
        return std::unexpected(BackendError::io);
    }
    if (auto w = _overlay->write(offset, in); !w) {
        if (w.error() == OverlayError::full) {
            ++_counters.overlay_full;
        }
        return std::unexpected(w.error() == OverlayError::out_of_range ? BackendError::out_of_range
                                                                       : BackendError::io);
    }
    ++_counters.writes;
    return {};
}

auto LazyImageBackend::read_image(std::uint64_t offset, std::span<std::byte> out)
    -> std::expected<void, BackendError> {
    const ImageManifest& m = _params.image->manifest();
    std::size_t pos = 0;
    while (pos < out.size()) {
        const std::uint64_t at = offset + pos;
        const auto chunk = static_cast<std::uint32_t>(at >> m.chunk_shift);
        const std::uint64_t within = at - m.chunk_offset(chunk);
        const std::size_t n =
            std::min<std::uint64_t>(out.size() - pos, m.chunk_length(chunk) - within);
        const auto piece = out.subspan(pos, n);
        if (m.is_hole(chunk)) {
            std::ranges::fill(piece, std::byte{0});  // plaintext zeros, even when encrypted
        } else {
            const auto arrived =
                std::ranges::find(_arrived, chunk, &decltype(_arrived)::value_type::first);
            if (_params.image->read(chunk, within, piece)) {
                ++_counters.cache_hits;
            } else if (arrived != _arrived.end()) {
                ++_counters.arrived_hits;
                std::copy_n(arrived->second->begin() + static_cast<std::ptrdiff_t>(within), n,
                            piece.begin());
            } else if (const auto failed = _failed.find(chunk); failed != _failed.end()) {
                // What a parked read waited for failed: fail it now rather
                // than wait out another deadline. The next read tries again.
                _failed.erase(failed);
                ++_counters.fetch_failures;
                return std::unexpected(BackendError::io);
            } else {
                ++_counters.fetches;
                const auto bytes = _params.fetcher->fetch(_params.image, chunk);
                if (!bytes) {
                    ++_counters.fetch_failures;
                    return std::unexpected(BackendError::io);
                }
                std::copy_n((*bytes)->begin() + static_cast<std::ptrdiff_t>(within), n,
                            piece.begin());
            }
            if (_img && !_img->decrypt(at / m.logical_block_size, piece, piece)) {
                return std::unexpected(BackendError::io);
            }
        }
        pos += n;
    }
    return {};
}

auto LazyImageBackend::read_ready(std::uint64_t offset, std::size_t len) -> bool {
    collect();
    if (!_params.waker || !_eph || !check(offset, len)) {
        return true;  // read() fails at once, or may block
    }
    const ImageManifest& m = _params.image->manifest();
    const std::uint32_t lbs = _params.logical_block_size;
    bool ready = true;
    std::optional<std::uint32_t> last;
    for (std::uint64_t at = offset; at < offset + len; at += lbs) {
        if (source(at / lbs) != Source::image) {
            continue;
        }
        const auto chunk = static_cast<std::uint32_t>(at >> m.chunk_shift);
        if (chunk != last) {
            last = chunk;
            ready = chunk_ready(chunk) && ready;  // start every fetch the range needs
        }
    }
    return ready;
}

auto LazyImageBackend::collect() -> void {
    std::vector<std::pair<std::uint32_t, FetchResult>> results;
    {
        const std::scoped_lock lock{_inbox->mutex};
        results.swap(_inbox->results);
    }
    for (auto& [chunk, result] : results) {
        _awaited.erase(chunk);
        if (result) {
            _failed.erase(chunk);
            _arrived.emplace_back(chunk, std::move(*result));
            if (_arrived.size() > max_arrived) {
                _arrived.pop_front();
            }
        } else {
            _failed.insert_or_assign(chunk, result.error());
        }
    }
}

auto LazyImageBackend::chunk_ready(std::uint32_t chunk) -> bool {
    const ImageManifest& m = _params.image->manifest();
    if (m.is_hole(chunk) || _params.image->resident(chunk) || _failed.contains(chunk) ||
        std::ranges::contains(_arrived, chunk, &decltype(_arrived)::value_type::first)) {
        return true;
    }
    if (_awaited.contains(chunk)) {
        return false;
    }
    auto started = _params.fetcher->fetch_async(_params.image, chunk,
                                                [inbox = _inbox, chunk](const FetchResult& result) {
                                                    {
                                                        const std::scoped_lock lock{inbox->mutex};
                                                        inbox->results.emplace_back(chunk, result);
                                                    }
                                                    inbox->waker->notify();
                                                });
    if (!started) {
        return true;  // read() reports the refusal
    }
    _awaited.insert(chunk);
    ++_counters.async_fetches;
    return false;
}

auto LazyImageBackend::readahead(std::uint64_t offset, std::uint64_t end) -> void {
    const ImageManifest& m = _params.image->manifest();
    const std::uint64_t this_chunk = offset >> m.chunk_shift;
    bool sequential = false;
    if (_last_end) {
        const std::uint64_t last_chunk = (*_last_end - 1) >> m.chunk_shift;
        sequential =
            offset == *_last_end || this_chunk == last_chunk || this_chunk == last_chunk + 1;
    }
    _window = sequential ? std::min(std::max(_window * 2, 1U), _params.max_readahead_chunks) : 0;
    _last_end = end;
    const std::uint64_t end_chunk = (end - 1) >> m.chunk_shift;
    for (std::uint64_t c = end_chunk + 1; c <= end_chunk + _window && c < m.chunk_count(); ++c) {
        const auto chunk = static_cast<std::uint32_t>(c);
        if (m.is_hole(chunk) || _params.image->resident(chunk)) {
            continue;
        }
        _params.fetcher->prefetch(_params.image, chunk);
        ++_counters.readahead;
    }
}

}  // namespace ak::oar::blk
