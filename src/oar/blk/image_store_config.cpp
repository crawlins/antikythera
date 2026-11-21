// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/image_store_config.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>

#include "oar/blk/sigv4.hpp"

namespace ak::oar::blk {

namespace {

constexpr std::string_view whitespace = " \t\r";
constexpr std::string_view https_scheme = "https://";
constexpr std::string_view http_scheme = "http://";

auto trim(std::string_view s) -> std::string_view {
    const auto from = s.find_first_not_of(whitespace);
    if (from == std::string_view::npos) {
        return {};
    }
    const auto to = s.find_last_not_of(whitespace);
    return s.substr(from, to - from + 1);
}

// A comment starts with '#' at the start of the line or after whitespace,
// so values may contain '#' (a secret key, say) when it is not preceded by
// a blank.
auto strip_comment(std::string_view line) -> std::string_view {
    for (std::size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '#' && (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t')) {
            return line.substr(0, i);
        }
    }
    return line;
}

auto parse_port(std::string_view s) -> std::optional<std::uint16_t> {
    std::uint16_t port = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), port);
    if (ec != std::errc{} || end != s.data() + s.size() || port == 0) {
        return std::nullopt;
    }
    return port;
}

// endpoint = scheme://host[:port], host a name or [IPv6]; nothing after.
auto parse_endpoint(std::string_view v, S3Config& c) -> bool {
    if (v.starts_with(https_scheme)) {
        c.tls = true;
        v.remove_prefix(https_scheme.size());
    } else if (v.starts_with(http_scheme)) {
        c.tls = false;
        v.remove_prefix(http_scheme.size());
    } else {
        return false;
    }
    std::string_view host;
    std::string_view rest;
    if (v.starts_with('[')) {
        const auto close = v.find(']');
        if (close == std::string_view::npos || close == 1) {
            return false;
        }
        host = v.substr(1, close - 1);
        rest = v.substr(close + 1);
    } else {
        const auto colon = v.find(':');
        host = v.substr(0, colon);
        rest = colon == std::string_view::npos ? std::string_view{} : v.substr(colon);
    }
    if (host.empty() || host.find_first_of("/?#@ ") != std::string_view::npos) {
        return false;
    }
    c.host = host;
    c.port = 0;
    if (!rest.empty()) {
        if (!rest.starts_with(':')) {
            return false;
        }
        const auto port = parse_port(rest.substr(1));
        if (!port) {
            return false;
        }
        c.port = *port;
    }
    return true;
}

}  // namespace

auto parse_image_store_config(std::string_view text)
    -> std::expected<ImageStoreConfig, std::string> {
    ImageStoreConfig out;
    std::set<std::string, std::less<>> seen;
    std::string access_key;
    std::string secret_key;
    std::size_t line_no = 0;
    while (!text.empty()) {
        const auto nl = text.find('\n');
        const std::string_view raw = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        ++line_no;
        const auto line = trim(strip_comment(raw));
        if (line.empty()) {
            continue;
        }
        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            return std::unexpected(std::format("line {}: expected key = value", line_no));
        }
        const auto key = trim(line.substr(0, eq));
        const auto value = trim(line.substr(eq + 1));
        if (!seen.emplace(key).second) {
            return std::unexpected(std::format("line {}: {} given twice", line_no, key));
        }
        if (value.empty()) {
            return std::unexpected(std::format("line {}: {} has no value", line_no, key));
        }
        if (key == "endpoint") {
            if (!parse_endpoint(value, out.s3)) {
                return std::unexpected(std::format(
                    "line {}: endpoint is http(s)://host[:port] or http(s)://[ipv6][:port]",
                    line_no));
            }
        } else if (key == "bucket") {
            out.s3.bucket = value;
        } else if (key == "prefix") {
            out.prefix = value;
        } else if (key == "region") {
            out.s3.region = value;
        } else if (key == "style") {
            if (value == "path") {
                out.s3.path_style = true;
            } else if (value == "virtual") {
                out.s3.path_style = false;
            } else {
                return std::unexpected(std::format("line {}: style is path or virtual", line_no));
            }
        } else if (key == "ca_file") {
            out.s3.ca_file = value;
        } else if (key == "access_key") {
            access_key = value;
        } else if (key == "secret_key") {
            secret_key = value;
        } else {
            return std::unexpected(std::format("line {}: unknown key {}", line_no, key));
        }
    }
    if (out.s3.host.empty()) {
        return std::unexpected("no endpoint");
    }
    if (out.s3.bucket.empty()) {
        return std::unexpected("no bucket");
    }
    if (access_key.empty() != secret_key.empty()) {
        return std::unexpected("access_key and secret_key go together");
    }
    if (!access_key.empty()) {
        out.s3.credentials = SigV4Credentials{.access_key = std::move(access_key),
                                              .secret_key = std::move(secret_key),
                                              .session_token = {}};
    }
    return out;
}

}  // namespace ak::oar::blk
