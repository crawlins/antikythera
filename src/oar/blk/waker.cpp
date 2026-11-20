// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/waker.hpp"

#include <cstdint>
#include <memory>

#include <sys/eventfd.h>
#include <unistd.h>

namespace ak::oar::blk {

auto Waker::create() -> std::shared_ptr<Waker> {
    const int fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) {
        return nullptr;
    }
    return std::shared_ptr<Waker>(new Waker(fd));
}

Waker::~Waker() {
    ::close(_fd);
}

auto Waker::notify() noexcept -> void {
    const std::uint64_t one = 1;
    // EAGAIN means the counter is saturated, which still reads as signalled.
    [[maybe_unused]] const auto n = ::write(_fd, &one, sizeof one);
}

auto Waker::drain() noexcept -> bool {
    std::uint64_t count = 0;
    return ::read(_fd, &count, sizeof count) == static_cast<ssize_t>(sizeof count);
}

}  // namespace ak::oar::blk
