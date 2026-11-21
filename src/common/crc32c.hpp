// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// CRC32C (Castagnoli, reflected polynomial 0x82F63B78), the checksum the
// hold wire protocol and ReplicaStore keep per block and per frame header
// (.kiro/specs/block-volume-service/ design "hold wire protocol",
// "Write and read paths"). The same function as iSCSI (RFC 3720 B.4),
// ext4 and NVMe/TCP.
//
// Portable table code everywhere; on x86-64 the SSE4.2 crc32 instruction
// when the CPU has it, picked once at run time so one binary runs on any
// x86-64. No dependency beyond the compiler.
//
// crc32c::of(data) is the finished checksum. To checksum in pieces, carry
// the raw state: finish(extend(extend(init, a), b)).

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <nmmintrin.h>
#define AK_CRC32C_X86 1
#endif

namespace ak::crc32c {

inline constexpr std::uint32_t polynomial = 0x82F6'3B78;  // reflected
inline constexpr std::uint32_t init = 0xFFFF'FFFF;

namespace detail {

inline constexpr auto table = [] {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t i = 0; i < t.size(); ++i) {
        std::uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1U) != 0 ? (c >> 1U) ^ polynomial : c >> 1U;
        }
        t[i] = c;
    }
    return t;
}();

[[nodiscard]] constexpr auto extend_portable(std::uint32_t state,
                                             std::span<const std::byte> data) noexcept
    -> std::uint32_t {
    for (const auto b : data) {
        state = table[(state ^ std::to_integer<std::uint32_t>(b)) & 0xFFU] ^ (state >> 8U);
    }
    return state;
}

#if defined(AK_CRC32C_X86)
[[nodiscard]]
__attribute__((target("sse4.2"))) inline auto extend_sse42(std::uint32_t state,
                                                           std::span<const std::byte> data) noexcept
    -> std::uint32_t {
    const std::byte* p = data.data();
    std::size_t n = data.size();
    std::uint64_t s = state;
    while (n >= sizeof(std::uint64_t)) {
        std::uint64_t word = 0;
        std::memcpy(&word, p, sizeof word);  // x86 is little-endian
        s = _mm_crc32_u64(s, word);
        p += sizeof word;
        n -= sizeof word;
    }
    auto s32 = static_cast<std::uint32_t>(s);
    while (n > 0) {
        s32 = _mm_crc32_u8(s32, std::to_integer<std::uint8_t>(*p));
        ++p;
        --n;
    }
    return s32;
}

[[nodiscard]] inline auto have_sse42() noexcept -> bool {
    static const bool have = static_cast<bool>(__builtin_cpu_supports("sse4.2"));
    return have;
}
#endif

}  // namespace detail

// True when this process uses the hardware instruction.
[[nodiscard]] inline auto hardware_accelerated() noexcept -> bool {
#if defined(AK_CRC32C_X86)
    return detail::have_sse42();
#else
    return false;
#endif
}

// Folds `data` into a raw (un-inverted) state that started at `init`.
[[nodiscard]] inline auto extend(std::uint32_t state, std::span<const std::byte> data) noexcept
    -> std::uint32_t {
#if defined(AK_CRC32C_X86)
    if (detail::have_sse42()) {
        return detail::extend_sse42(state, data);
    }
#endif
    return detail::extend_portable(state, data);
}

[[nodiscard]] constexpr auto finish(std::uint32_t state) noexcept -> std::uint32_t {
    return ~state;
}

// The CRC32C of `data`.
[[nodiscard]] inline auto of(std::span<const std::byte> data) noexcept -> std::uint32_t {
    return finish(extend(init, data));
}

// The portable path alone, usable in constant expressions and in tests
// that compare it with the hardware path.
[[nodiscard]] constexpr auto of_portable(std::span<const std::byte> data) noexcept
    -> std::uint32_t {
    return finish(detail::extend_portable(init, data));
}

}  // namespace ak::crc32c
