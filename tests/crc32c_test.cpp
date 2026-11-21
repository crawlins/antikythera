// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ Requirement 5.4: CRC32C against the
// published check value and the RFC 3720 B.4 vectors, on both the
// portable and the hardware path, whole and in pieces.

#define BOOST_TEST_MODULE crc32c_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "common/crc32c.hpp"
#include "test_support.hpp"

using ak::test::unit_timeout_seconds;

namespace {

auto bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (const char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

constexpr std::size_t rfc_len = 32;

auto filled(std::uint8_t (*f)(std::size_t)) -> std::array<std::byte, rfc_len> {
    std::array<std::byte, rfc_len> a{};
    for (std::size_t i = 0; i < a.size(); ++i) {
        a[i] = std::byte{f(i)};
    }
    return a;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(crc32c, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(check_value) {
    const auto b = bytes("123456789");
    BOOST_TEST(ak::crc32c::of(b) == 0xE306'9283U);
    BOOST_TEST(ak::crc32c::of_portable(b) == 0xE306'9283U);
    BOOST_TEST(ak::crc32c::of({}) == 0U);
}

BOOST_AUTO_TEST_CASE(rfc3720_vectors) {
    const auto zeros = filled([](std::size_t) -> std::uint8_t { return 0; });
    const auto ones = filled([](std::size_t) -> std::uint8_t { return 0xFF; });
    const auto up = filled([](std::size_t i) { return static_cast<std::uint8_t>(i); });
    const auto down =
        filled([](std::size_t i) { return static_cast<std::uint8_t>(rfc_len - 1 - i); });
    BOOST_TEST(ak::crc32c::of(zeros) == 0x8A91'36AAU);
    BOOST_TEST(ak::crc32c::of(ones) == 0x62A8'AB43U);
    BOOST_TEST(ak::crc32c::of(up) == 0x46DD'794EU);
    BOOST_TEST(ak::crc32c::of(down) == 0x113F'DB5CU);
}

BOOST_AUTO_TEST_CASE(hardware_matches_portable_at_every_length_and_split) {
    BOOST_TEST_MESSAGE("hardware path: " << ak::crc32c::hardware_accelerated());
    std::vector<std::byte> b(100);
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = std::byte{static_cast<std::uint8_t>((i * 37U) + 11U)};
    }
    for (std::size_t n = 0; n <= b.size(); ++n) {
        const auto s = std::span<const std::byte>{b}.first(n);
        const auto want = ak::crc32c::of_portable(s);
        BOOST_TEST(ak::crc32c::of(s) == want);
        for (std::size_t cut = 0; cut <= n; cut += 7) {
            const auto st = ak::crc32c::extend(ak::crc32c::init, s.first(cut));
            BOOST_TEST(ak::crc32c::finish(ak::crc32c::extend(st, s.subspan(cut))) == want);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
