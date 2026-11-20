// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 8.2, 8.9, 8.10 and 7.3:
// S3ObjectStore against an S3 emulator on loopback (plain and TLS) that
// checks every request's Signature V4, and against servers that misbehave:
// wrong ranges, long or short bodies, chunked encoding, error statuses,
// silence and idle-closed keep-alive connections. Then the whole image
// volume path (fetcher, cache, LazyImageBackend) over S3.
//
// With AK_S3_TEST_ENDPOINT=http://host:port (plus AK_S3_TEST_ACCESS_KEY,
// AK_S3_TEST_SECRET_KEY and AK_S3_TEST_BUCKET, an existing bucket) one
// more case runs against a real S3-compatible server (MinIO, SeaweedFS):
// it uploads an image with a signed PUT and reads it back lazily. It is
// skipped otherwise.

#define BOOST_TEST_MODULE s3_object_store_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "oar/blk/chunk_cache.hpp"
#include "oar/blk/fetcher.hpp"
#include "oar/blk/image_manifest.hpp"
#include "oar/blk/lazy_image_backend.hpp"
#include "oar/blk/s3_object_store.hpp"
#include "oar/blk/sigv4.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "test_support.hpp"
#include "tls_test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, FetchError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, S3ConfigError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk

namespace blk = ak::oar::blk;
using ak::test::unit_timeout_seconds;
using blk::FetchError;
using Clock = blk::ObjectStore::Clock;

namespace {

constexpr std::chrono::seconds io_deadline{5};
const blk::SigV4Credentials test_creds{
    .access_key = "AKTESTREADER", .secret_key = "testsecretkey0123456789", .session_token = ""};

auto soon() -> Clock::time_point {
    return Clock::now() + io_deadline;
}

struct Request {
    std::string method;
    std::string target;
    std::map<std::string, std::string> headers;  // lowercase names
    std::string head;
};

struct Reply {
    std::string bytes;
    bool close{false};  // close the connection after sending
    bool stall{false};  // send nothing and hold the connection
};

auto reply(std::string bytes) -> Reply {
    return {.bytes = std::move(bytes), .close = false, .stall = false};
}

auto s3_config(std::string host, std::uint16_t port, std::string bucket,
               std::optional<blk::SigV4Credentials> creds, bool tls = false,
               std::string ca_file = {}) -> blk::S3Config {
    blk::S3Config c;
    c.tls = tls;
    c.host = std::move(host);
    c.port = port;
    c.bucket = std::move(bucket);
    c.credentials = std::move(creds);
    c.ca_file = std::move(ca_file);
    return c;
}

// A loopback HTTP/1.1 server; `handler` answers each request. Optionally TLS.
class MockServer {
public:
    using Handler = std::function<Reply(const Request&)>;

    explicit MockServer(Handler handler, const ak::test::Pem* tls = nullptr)
        : _handler{std::move(handler)} {
        if (tls != nullptr) {
            _ctx = SSL_CTX_new(TLS_server_method());
            BOOST_REQUIRE(_ctx != nullptr);
            BIO* cb = BIO_new_mem_buf(tls->cert.data(), static_cast<int>(tls->cert.size()));
            X509* cert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
            BIO_free(cb);
            BIO* kb = BIO_new_mem_buf(tls->key.data(), static_cast<int>(tls->key.size()));
            EVP_PKEY* key = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
            BIO_free(kb);
            BOOST_REQUIRE(SSL_CTX_use_certificate(_ctx, cert) == 1);
            BOOST_REQUIRE(SSL_CTX_use_PrivateKey(_ctx, key) == 1);
            X509_free(cert);
            EVP_PKEY_free(key);
        }
        _listen = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        BOOST_REQUIRE(_listen >= 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE(::bind(_listen, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
        BOOST_REQUIRE(::listen(_listen, 16) == 0);
        socklen_t len = sizeof(addr);
        BOOST_REQUIRE(::getsockname(_listen, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
        _port = ntohs(addr.sin_port);
        _thread = std::thread{[this] { serve(); }};
    }
    MockServer(const MockServer&) = delete;
    auto operator=(const MockServer&) -> MockServer& = delete;
    MockServer(MockServer&&) = delete;
    auto operator=(MockServer&&) -> MockServer& = delete;
    ~MockServer() {
        _stop = true;
        ::shutdown(_listen, SHUT_RDWR);
        _thread.join();
        ::close(_listen);
        SSL_CTX_free(_ctx);
    }

    [[nodiscard]] auto port() const -> std::uint16_t { return _port; }
    [[nodiscard]] auto accepted() const -> int { return _accepted.load(); }
    // Closes every idle connection, as a server's keep-alive timeout would.
    auto drop_idle() -> void { _drop_idle = true; }
    auto keep_idle() -> void { _drop_idle = false; }

private:
    auto serve() -> void {
        while (!_stop) {
            pollfd p{.fd = _listen, .events = POLLIN, .revents = 0};
            if (::poll(&p, 1, 50) <= 0) {
                continue;
            }
            const int fd = ::accept4(_listen, nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) {
                continue;
            }
            ++_accepted;
            _connections.emplace_back([this, fd] {
                connection(fd);
                ::close(fd);
            });
        }
        for (auto& t : _connections) {
            t.join();
        }
    }

    auto connection(int fd) -> void {
        SSL* ssl = nullptr;
        if (_ctx != nullptr) {
            ssl = SSL_new(_ctx);
            SSL_set_fd(ssl, fd);
            if (SSL_accept(ssl) != 1) {
                ERR_clear_error();
                SSL_free(ssl);
                return;
            }
        }
        auto rd = [&](char* buf, int n) -> int {
            return ssl != nullptr ? SSL_read(ssl, buf, n)
                                  : static_cast<int>(::recv(fd, buf, static_cast<size_t>(n), 0));
        };
        auto wr = [&](const std::string& s) {
            if (ssl != nullptr) {
                SSL_write(ssl, s.data(), static_cast<int>(s.size()));
            } else {
                ::send(fd, s.data(), s.size(), MSG_NOSIGNAL);
            }
        };
        std::string pending;
        while (!_stop) {
            pollfd p{.fd = fd, .events = POLLIN, .revents = 0};
            if (::poll(&p, 1, 50) == 0 && (ssl == nullptr || SSL_pending(ssl) == 0)) {
                if (_drop_idle.load()) {
                    break;
                }
                continue;
            }
            std::array<char, 4096> buf{};
            const int n = rd(buf.data(), static_cast<int>(buf.size()));
            if (n <= 0) {
                break;
            }
            pending.append(buf.data(), static_cast<std::size_t>(n));
            const auto end = pending.find("\r\n\r\n");
            if (end == std::string::npos) {
                continue;
            }
            Request req;
            req.head = pending.substr(0, end + 4);
            pending.erase(0, end + 4);
            parse(req);
            const Reply reply = _handler(req);
            if (reply.stall) {
                std::this_thread::sleep_for(std::chrono::milliseconds{300});
                break;
            }
            wr(reply.bytes);
            if (reply.close) {
                break;
            }
        }
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }

    static auto parse(Request& req) -> void {
        std::size_t pos = req.head.find("\r\n");
        const std::string line = req.head.substr(0, pos);
        const auto sp1 = line.find(' ');
        const auto sp2 = line.find(' ', sp1 + 1);
        req.method = line.substr(0, sp1);
        req.target = line.substr(sp1 + 1, sp2 - sp1 - 1);
        while (true) {
            const auto next = req.head.find("\r\n", pos + 2);
            if (next == std::string::npos || next == pos + 2) {
                break;
            }
            const std::string h = req.head.substr(pos + 2, next - pos - 2);
            const auto colon = h.find(':');
            std::string name = h.substr(0, colon);
            std::ranges::transform(name, name.begin(),
                                   [](char c) { return static_cast<char>(std::tolower(c)); });
            req.headers[name] = h.substr(colon + 2);
            pos = next;
        }
    }

    Handler _handler;
    SSL_CTX* _ctx{nullptr};
    int _listen{-1};
    std::uint16_t _port{0};
    std::atomic<bool> _stop{false};
    std::atomic<bool> _drop_idle{false};
    std::atomic<int> _accepted{0};
    std::vector<std::thread> _connections;  // owned by the accept thread
    std::thread _thread;
};

// An S3 bucket in memory that insists on a valid signature.
class Emulator {
public:
    std::map<std::string, std::string> objects;  // "/bucket/key" -> bytes
    std::atomic<int> requests{0};
    std::atomic<int> bad_signatures{0};

    [[nodiscard]] auto last_range() -> std::string {
        const std::scoped_lock lock{_mutex};
        return _last_range;
    }

    auto operator()(const Request& r) -> Reply {
        ++requests;
        if (!signature_ok(r)) {
            ++bad_signatures;
            return reply("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        }
        const auto it = objects.find(r.target);
        if (r.method != "GET" || it == objects.end()) {
            return reply("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        }
        const std::string& obj = it->second;
        const auto range = r.headers.find("range");
        if (range == r.headers.end()) {
            return reply("HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(obj.size()) +
                         "\r\n\r\n" + obj);
        }
        {
            const std::scoped_lock lock{_mutex};
            _last_range = range->second;
        }
        const auto spec = range->second.substr(6);  // "bytes="
        const auto dash = spec.find('-');
        const std::uint64_t first = std::stoull(spec.substr(0, dash));
        std::uint64_t last = std::stoull(spec.substr(dash + 1));
        if (first >= obj.size()) {
            return reply("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n");
        }
        last = std::min<std::uint64_t>(last, obj.size() - 1);
        const std::string body = obj.substr(first, last - first + 1);
        return reply("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes " +
                     std::to_string(first) + "-" + std::to_string(last) + "/" +
                     std::to_string(obj.size()) +
                     "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body);
    }

private:
    std::mutex _mutex;
    std::string _last_range;

    static auto signature_ok(const Request& r) -> bool {
        const auto auth = r.headers.find("authorization");
        if (auth == r.headers.end()) {
            return false;
        }
        std::vector<std::pair<std::string, std::string>> signed_headers;
        for (const auto& [k, v] : r.headers) {
            if (k != "authorization") {
                signed_headers.emplace_back(k, v);
            }
        }
        const auto date = r.headers.find("x-amz-date");
        if (date == r.headers.end()) {
            return false;
        }
        const auto expect = blk::sigv4_authorization({.method = r.method,
                                                      .canonical_uri = r.target,
                                                      .headers = signed_headers,
                                                      .payload_hash = blk::empty_payload_sha256,
                                                      .amz_date = date->second,
                                                      .region = "us-east-1"},
                                                     test_creds);
        return expect && *expect == auth->second;
    }
};

auto plain_store(std::uint16_t port, std::optional<blk::SigV4Credentials> creds = test_creds)
    -> std::unique_ptr<blk::S3ObjectStore> {
    auto s = blk::S3ObjectStore::create(s3_config("127.0.0.1", port, "images", std::move(creds)));
    BOOST_REQUIRE(s.has_value());
    return std::move(*s);
}

auto pattern(std::size_t n) -> std::string {
    std::string s(n, '\0');
    for (std::size_t i = 0; i < n; ++i) {
        s[i] = static_cast<char>('a' + (i % 26));
    }
    return s;
}

auto as_string(std::span<const std::byte> b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

}  // namespace

BOOST_AUTO_TEST_CASE(signed_range_gets, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Emulator emu;
    emu.objects["/images/a/data"] = pattern(1000);
    emu.objects["/images/odd%20name%2B/data"] = "xyz";  // as signed and sent
    MockServer server{std::ref(emu)};
    auto store = plain_store(server.port());

    std::vector<std::byte> out(100);
    BOOST_REQUIRE(store->get_range("a/data", 200, out, soon()).has_value());
    BOOST_TEST(as_string(out) == pattern(1000).substr(200, 100));
    BOOST_TEST(emu.last_range() == "bytes=200-299");
    // Keys are encoded the way the signature expects.
    std::vector<std::byte> three(3);
    BOOST_REQUIRE(store->get_range("odd name+/data", 0, three, soon()).has_value());
    BOOST_TEST(as_string(three) == "xyz");
    // Whole objects.
    const auto whole = store->get("a/data", 4096, soon());
    BOOST_REQUIRE(whole.has_value());
    BOOST_TEST(as_string(*whole) == pattern(1000));
    BOOST_TEST(store->get("a/data", 999, soon()).error() == FetchError::too_large);
    BOOST_TEST(emu.bad_signatures.load() == 0);
    // One connection, kept alive (the too_large answer was complete and
    // well-formed, but its body was never read, so that one is dropped).
    BOOST_TEST(server.accepted() == 1);
    BOOST_TEST(store->counters().reused == 3U);
}

BOOST_AUTO_TEST_CASE(maps_statuses, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Emulator emu;
    emu.objects["/images/a/data"] = pattern(10);
    MockServer server{std::ref(emu)};
    auto store = plain_store(server.port());
    std::vector<std::byte> out(5);
    BOOST_TEST(store->get_range("missing/data", 0, out, soon()).error() == FetchError::not_found);
    BOOST_TEST(store->get_range("a/data", 20, out, soon()).error() == FetchError::not_found);
    auto wrong = plain_store(server.port(), blk::SigV4Credentials{.access_key = "AKTESTREADER",
                                                                  .secret_key = "wrong",
                                                                  .session_token = ""});
    BOOST_TEST(wrong->get_range("a/data", 0, out, soon()).error() == FetchError::denied);
    auto anonymous = plain_store(server.port(), std::nullopt);
    BOOST_TEST(anonymous->get_range("a/data", 0, out, soon()).error() == FetchError::denied);
}

BOOST_AUTO_TEST_CASE(holds_responses_to_the_request,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::mutex mutex;  // the handler runs on the server's thread
    std::string next;
    bool close = false;
    MockServer server{[&](const Request&) {
        const std::scoped_lock lock{mutex};
        return Reply{.bytes = next, .close = close, .stall = false};
    }};
    auto set = [&](std::string reply, bool close_after) {
        const std::scoped_lock lock{mutex};
        next = std::move(reply);
        close = close_after;
    };
    auto store = plain_store(server.port());
    std::vector<std::byte> out(4);
    bool closing = false;
    auto expect = [&](const std::string& reply, FetchError e) {
        set(reply, closing);
        BOOST_TEST_CONTEXT(reply) {
            BOOST_TEST(store->get_range("k", 10, out, soon()).error() == e);
        }
    };
    // Wrong range, wrong length, unknown length, full object, chunked.
    expect("HTTP/1.1 206 P\r\nContent-Range: bytes 11-14/100\r\nContent-Length: 4\r\n\r\nabcd",
           FetchError::bad_response);
    expect("HTTP/1.1 206 P\r\nContent-Range: bytes 10-13/100\r\nContent-Length: 5\r\n\r\nabcde",
           FetchError::bad_response);
    expect("HTTP/1.1 206 P\r\nContent-Range: bytes 10-13/100\r\n\r\nabcd",
           FetchError::bad_response);
    expect("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd", FetchError::bad_response);
    expect("HTTP/1.1 206 P\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
           FetchError::bad_response);
    expect("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", FetchError::bad_response);
    expect("HTTP/1.1 503 Slow Down\r\nContent-Length: 0\r\n\r\n", FetchError::io);
    expect("HTTP/1.1 429 Too Many\r\nContent-Length: 0\r\n\r\n", FetchError::io);
    expect("garbage\r\n\r\n", FetchError::bad_response);
    // More bytes than declared in the same packet.
    expect("HTTP/1.1 206 P\r\nContent-Range: bytes 10-13/100\r\nContent-Length: 4\r\n\r\nabcdEXTRA",
           FetchError::bad_response);
    // A short body: the server closes mid-body.
    closing = true;
    expect("HTTP/1.1 206 P\r\nContent-Range: bytes 10-13/100\r\nContent-Length: 4\r\n\r\nab",
           FetchError::bad_response);
    // And the right answer works.
    set("HTTP/1.1 206 P\r\nContent-Range: bytes 10-13/*\r\nContent-Length: 4\r\n\r\nabcd", true);
    BOOST_REQUIRE(store->get_range("k", 10, out, soon()).has_value());
    BOOST_TEST(as_string(out) == "abcd");
    // A whole object asked for by range may come back as 200.
    set("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nwxyz", true);
    BOOST_REQUIRE(store->get_range("k", 0, out, soon()).has_value());
    BOOST_TEST(as_string(out) == "wxyz");
}

BOOST_AUTO_TEST_CASE(gives_up_at_the_deadline, *boost::unit_test::timeout(unit_timeout_seconds)) {
    MockServer server{
        [](const Request&) { return Reply{.bytes = {}, .close = false, .stall = true}; }};
    auto store = plain_store(server.port());
    std::vector<std::byte> out(4);
    const auto start = Clock::now();
    const auto r = store->get_range("k", 0, out, Clock::now() + std::chrono::milliseconds{100});
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error() == FetchError::timed_out);
    BOOST_TEST((Clock::now() - start < std::chrono::seconds{2}));
    // Nothing listening: a connection error, not a hang.
    const std::uint16_t port = server.port();
    auto none = plain_store(static_cast<std::uint16_t>(port == 1 ? 2 : 1));
    BOOST_TEST(none->get_range("k", 0, out, soon()).error() == FetchError::io);
}

BOOST_AUTO_TEST_CASE(replaces_idle_closed_connections,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Emulator emu;
    emu.objects["/images/a/data"] = pattern(64);
    MockServer server{std::ref(emu)};
    auto store = plain_store(server.port());
    std::vector<std::byte> out(8);
    BOOST_REQUIRE(store->get_range("a/data", 0, out, soon()).has_value());
    server.drop_idle();
    std::this_thread::sleep_for(std::chrono::milliseconds{200});
    server.keep_idle();
    BOOST_REQUIRE(store->get_range("a/data", 8, out, soon()).has_value());
    BOOST_TEST(as_string(out) == pattern(64).substr(8, 8));
    BOOST_TEST(store->counters().stale == 1U);
    BOOST_TEST(server.accepted() == 2);
}

BOOST_AUTO_TEST_CASE(tls_verifies_the_server, *boost::unit_test::timeout(unit_timeout_seconds)) {
    ak::test::TestCa ca{"s3-ca"};
    const auto leaf = ca.issue("s3", "IP:127.0.0.1");
    Emulator emu;
    emu.objects["/images/a/data"] = pattern(100);
    MockServer server{std::ref(emu), &leaf};
    const auto dir = std::filesystem::temp_directory_path() /
                     ("ak-s3-ca-" + std::to_string(::getpid()) + ".pem");
    {
        std::FILE* f = std::fopen(dir.c_str(), "w");
        BOOST_REQUIRE(f != nullptr);
        const auto pem = ca.cert_pem();
        std::fwrite(pem.data(), 1, pem.size(), f);
        std::fclose(f);
    }
    auto store = blk::S3ObjectStore::create(
        s3_config("127.0.0.1", server.port(), "images", test_creds, true, dir.string()));
    BOOST_REQUIRE(store.has_value());
    std::vector<std::byte> out(10);
    BOOST_REQUIRE((*store)->get_range("a/data", 50, out, soon()).has_value());
    BOOST_TEST(as_string(out) == pattern(100).substr(50, 10));

    // Another CA does not vouch for this server.
    ak::test::TestCa other{"other-ca"};
    {
        std::FILE* f = std::fopen(dir.c_str(), "w");
        const auto pem = other.cert_pem();
        std::fwrite(pem.data(), 1, pem.size(), f);
        std::fclose(f);
    }
    auto untrusting = blk::S3ObjectStore::create(
        s3_config("127.0.0.1", server.port(), "images", test_creds, true, dir.string()));
    BOOST_REQUIRE(untrusting.has_value());
    BOOST_TEST((*untrusting)->get_range("a/data", 0, out, soon()).error() == FetchError::denied);
    std::filesystem::remove(dir);
    BOOST_TEST(blk::S3ObjectStore::create(
                   s3_config("127.0.0.1", 0, "images", std::nullopt, true, dir.string()))
                   .error() == blk::S3ConfigError::bad_ca_file);
}

BOOST_AUTO_TEST_CASE(refuses_bad_configs, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(blk::S3ObjectStore::create(s3_config("", 0, "b", std::nullopt)).error() ==
               blk::S3ConfigError::no_host);
    BOOST_TEST(blk::S3ObjectStore::create(s3_config("h", 0, "", std::nullopt)).error() ==
               blk::S3ConfigError::no_bucket);
    auto vhost = s3_config("h", 0, "Bad_Bucket", std::nullopt);
    vhost.path_style = false;
    BOOST_TEST(blk::S3ObjectStore::create(vhost).error() == blk::S3ConfigError::no_bucket);
}

namespace {

// Builds an image of `chunks` 64 KiB chunks; returns its name and puts the
// manifest and data through `put(key, bytes)`.
auto publish_image(const std::function<void(const std::string&, const std::string&)>& put,
                   std::uint32_t chunks, std::string& data) -> blk::ImageDigest {
    constexpr std::uint64_t chunk = 64ULL * 1024;
    data = pattern(chunks * chunk);
    blk::ImageManifest m;
    m.chunk_shift = blk::min_chunk_shift;
    m.image_bytes = data.size();
    for (std::uint32_t c = 0; c < chunks; ++c) {
        const auto piece = std::string_view{data}.substr(c * chunk, chunk);
        m.chunks.push_back(
            *blk::sha256_digest(std::as_bytes(std::span{piece.data(), piece.size()})));
    }
    const auto bytes = blk::encode_manifest(m);
    BOOST_REQUIRE(bytes.has_value());
    const auto name = *blk::sha256_digest(*bytes);
    const auto hex = blk::image_name_hex(name);
    put(blk::image_manifest_key("images", hex), as_string(*bytes));
    put(blk::image_data_key("images", hex), data);
    return name;
}

auto boot_image(blk::ObjectStore& store, const blk::ImageDigest& name, const std::string& data)
    -> void {
    const auto hex = blk::image_name_hex(name);
    const auto raw = store.get(blk::image_manifest_key("images", hex),
                               blk::manifest_header_size + (32ULL << 20U), soon());
    BOOST_REQUIRE(raw.has_value());
    const auto manifest = blk::decode_named_manifest(*raw, name);
    BOOST_REQUIRE(manifest.has_value());
    std::string tmpl = (std::filesystem::temp_directory_path() / "ak-s3img-XXXXXX").string();
    BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
    const std::filesystem::path dir{tmpl};
    {
        auto cache = blk::ChunkCache::create(dir, 1ULL << 22U);
        BOOST_REQUIRE(cache.has_value());
        auto fetcher = blk::Fetcher::create(store, {});
        auto image = (*cache)->open_image(name, *manifest, blk::image_data_key("images", hex));
        BOOST_REQUIRE(image.has_value());
        auto backend = blk::LazyImageBackend::create({.image = *image,
                                                      .fetcher = fetcher.get(),
                                                      .overlay_dir = dir,
                                                      .capacity_bytes = manifest->image_bytes,
                                                      .logical_block_size = 512,
                                                      .max_readahead_chunks = 2,
                                                      .waker = nullptr});
        BOOST_REQUIRE(backend.has_value());
        std::array<std::byte, blk::xts_key_size> key{};
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<std::byte>(i * 3 + (i < 32 ? 1 : 200));
        }
        BOOST_REQUIRE((*backend)->load_keys(key, std::nullopt).has_value());
        auto cipher = blk::XtsCipher::create(key, 512);
        BOOST_REQUIRE(cipher.has_value());
        std::vector<std::byte> out(32768);
        for (std::uint64_t at = 0; at < manifest->image_bytes; at += out.size()) {
            BOOST_REQUIRE((*backend)->read(at, out).has_value());
            BOOST_REQUIRE(cipher->decrypt(at / 512, out, out).has_value());
            BOOST_REQUIRE(as_string(out) == data.substr(at, out.size()));
        }
        BOOST_TEST((*backend)->counters().readahead > 0U);
        fetcher->drain();
    }
    std::filesystem::remove_all(dir);
}

}  // namespace

BOOST_AUTO_TEST_CASE(image_volume_over_s3, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Emulator emu;
    std::string data;
    const auto name =
        publish_image([&](const std::string& key,
                          const std::string& bytes) { emu.objects["/images/" + key] = bytes; },
                      6, data);
    MockServer server{std::ref(emu)};
    auto store = plain_store(server.port());
    boot_image(*store, name, data);
    BOOST_TEST(emu.bad_signatures.load() == 0);
}

// A signed PUT, only for seeding a real server in the test below.
namespace {
auto put_object(const std::string& host, std::uint16_t port, const std::string& bucket,
                const blk::SigV4Credentials& creds, const std::string& key, const std::string& body)
    -> bool {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }
    const std::string uri = blk::s3_uri_encode_path("/" + bucket + "/" + key);
    const std::string date = blk::amz_date(std::chrono::system_clock::now());
    const std::string hash = *blk::sha256_hex(body);
    const std::string host_header = host + ":" + std::to_string(port);
    std::vector<std::pair<std::string, std::string>> headers{
        {"host", host_header}, {"x-amz-content-sha256", hash}, {"x-amz-date", date}};
    const auto auth = blk::sigv4_authorization({.method = "PUT",
                                                .canonical_uri = uri,
                                                .headers = headers,
                                                .payload_hash = hash,
                                                .amz_date = date,
                                                .region = "us-east-1"},
                                               creds);
    std::string req = "PUT " + uri + " HTTP/1.1\r\nhost: " + host_header +
                      "\r\nx-amz-content-sha256: " + hash + "\r\nx-amz-date: " + date +
                      "\r\nauthorization: " + *auth +
                      "\r\ncontent-length: " + std::to_string(body.size()) +
                      "\r\nconnection: close\r\n\r\n" + body;
    std::size_t sent = 0;
    while (sent < req.size()) {
        const ssize_t n = ::send(fd, req.data() + sent, req.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            ::close(fd);
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    std::array<char, 64> resp{};
    const ssize_t n = ::recv(fd, resp.data(), resp.size(), 0);
    ::close(fd);
    return n > 12 && std::string_view{resp.data(), 12} == "HTTP/1.1 200";
}
}  // namespace

BOOST_AUTO_TEST_CASE(real_s3_compatible_server, *boost::unit_test::timeout(120)) {
    const char* endpoint = std::getenv("AK_S3_TEST_ENDPOINT");
    if (endpoint == nullptr) {
        BOOST_TEST_MESSAGE("AK_S3_TEST_ENDPOINT not set: skipped");
        return;
    }
    // http://host:port only: the test seeds over plain HTTP.
    const std::string ep{endpoint};
    BOOST_REQUIRE(ep.starts_with("http://"));
    const auto colon = ep.rfind(':');
    const std::string host = ep.substr(7, colon - 7);
    const auto port = static_cast<std::uint16_t>(std::stoi(ep.substr(colon + 1)));
    const auto env = [](const char* n) {
        const char* v = std::getenv(n);
        BOOST_REQUIRE_MESSAGE(v != nullptr, n);
        return std::string{v};
    };
    const blk::SigV4Credentials creds{.access_key = env("AK_S3_TEST_ACCESS_KEY"),
                                      .secret_key = env("AK_S3_TEST_SECRET_KEY"),
                                      .session_token = ""};
    const std::string bucket = env("AK_S3_TEST_BUCKET");
    std::string data;
    const auto name = publish_image(
        [&](const std::string& key, const std::string& bytes) {
            BOOST_REQUIRE_MESSAGE(put_object(host, port, bucket, creds, key, bytes), key);
        },
        8, data);
    auto store = blk::S3ObjectStore::create(s3_config(host, port, bucket, creds));
    BOOST_REQUIRE(store.has_value());
    boot_image(**store, name, data);
    std::vector<std::byte> out(16);
    BOOST_TEST((*store)->get_range("images/nope/data", 0, out, soon()).error() ==
               FetchError::not_found);
}
