// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Wakes the role thread from another thread (.kiro/specs/oar-blk-data-plane/
// design "Asynchronous misses"): an eventfd that fetcher workers signal when
// a chunk a parked request waits for has arrived. The role's event loop
// polls fd(), and drains it before looking at what arrived, so a signal
// that comes in between is not lost: it leaves the fd readable for the
// next round.
//
// notify() is thread-safe and never blocks; drain() and fd() belong to the
// role thread.

#include <memory>

namespace ak::oar::blk {

class Waker {
public:
    // nullptr if the eventfd could not be created.
    [[nodiscard]] static auto create() -> std::shared_ptr<Waker>;

    Waker(const Waker&) = delete;
    auto operator=(const Waker&) -> Waker& = delete;
    Waker(Waker&&) = delete;
    auto operator=(Waker&&) -> Waker& = delete;
    ~Waker();

    auto notify() noexcept -> void;
    // Clears pending signals; true if there were any.
    auto drain() noexcept -> bool;
    [[nodiscard]] auto fd() const noexcept -> int { return _fd; }

private:
    explicit Waker(int fd) noexcept : _fd{fd} {}

    int _fd;
};

}  // namespace ak::oar::blk
