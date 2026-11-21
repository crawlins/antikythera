// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirement 3 (task 6): the storage role
// behind helm's sideband. Volume files, prepare/deliver/clean on a
// function whose transport swaps between a placeholder and the attached
// volume, the attach-window wait for the key, rewrap and delete, and the
// whole path from helm's KeyStore through OarLink to guest I/O.

#define BOOST_TEST_MODULE blk_role_test
#include <boost/test/unit_test.hpp>

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <mutex>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "common/wire.hpp"
#include "helm/key_store.hpp"
#include "helm/oar_link.hpp"
#include "helm/secure_element.hpp"
#include "helm/sideband_binding.hpp"
#include "oar/blk/blk_role.hpp"
#include "oar/blk/file_backend.hpp"
#include "oar/blk/image_manifest.hpp"
#include "oar/blk/image_pack.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

// Boost.Test's customization point for types it cannot print itself.
namespace std {  // NOLINT(cert-dcl58-cpp): boost_test_print_type is found by ADL
auto boost_test_print_type(std::ostream& os, std::byte b) -> std::ostream& {
    return os << "0x" << std::hex << std::to_integer<unsigned>(b) << std::dec;
}
}  // namespace std

namespace blk = ak::oar::blk;
namespace oar = ak::helm::oar;
namespace vio = ak::oar::virtio;
using ak::test::Buffer;
using ak::test::GuestRam;
using ak::test::RecordingInterrupts;
using ak::test::unit_timeout_seconds;
using ak::test::VirtioDriver;
using blk::RequestType;
using blk::Status;

namespace {

constexpr std::uint64_t vm_one = 0x101;
constexpr std::uint64_t vm_two = 0x102;
constexpr std::uint64_t vol_one = 0x201;
constexpr std::uint64_t vol_two = 0x202;
constexpr std::uint64_t volume_sectors = 256;  // 128 KiB
constexpr std::uint32_t test_seg_max = 4;
constexpr std::uint32_t test_max_transfer = 16 * 1024;
constexpr std::size_t function_count = 2;
constexpr oar::FunctionNumber fn0 = 0;
constexpr oar::FunctionNumber fn1 = 1;
constexpr std::uint16_t queue0 = 0;
constexpr std::size_t half_key = blk::xts_key_size / 2;
constexpr std::uint8_t data_key_base = 0x11;
constexpr std::uint8_t tweak_key_base = 0x91;
constexpr std::byte status_canary{0xAA};
constexpr std::uint8_t wrapped_fill = 0x5C;
constexpr std::uint8_t rewrapped_fill = 0x6D;
constexpr std::size_t wrapped_size = 95;
constexpr std::uint64_t marker_sector = 12;
constexpr std::uint64_t far_sector = 200;
constexpr auto serve_poll = std::chrono::milliseconds{5};
constexpr auto link_timeout = std::chrono::seconds{5};
constexpr ak::helm::LinkAddress helm_side{
    .local_addr = 0x08, .peer_addr = 0x12, .local_eid = 8, .peer_eid = 18};

auto test_key() -> std::array<std::byte, blk::xts_key_size> {
    std::array<std::byte, blk::xts_key_size> k{};
    for (std::size_t i = 0; i < half_key; ++i) {
        k[i] = static_cast<std::byte>(data_key_base + i);
        k[half_key + i] = static_cast<std::byte>(tweak_key_base + i);
    }
    return k;
}

// A recognisable guest pattern, one sector long.
auto marker() -> std::vector<std::byte> {
    std::vector<std::byte> out(blk::sector_size);
    constexpr std::string_view text = "antikythera-plaintext-marker:";
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::byte>(text[i % text.size()]);
    }
    return out;
}

auto file_bytes(const std::filesystem::path& p) -> std::vector<std::byte> {
    std::ifstream in{p, std::ios::binary};
    const std::vector<char> raw{std::istreambuf_iterator<char>{in},
                                std::istreambuf_iterator<char>{}};
    std::vector<std::byte> out(raw.size());
    std::ranges::transform(raw, out.begin(), [](char c) { return static_cast<std::byte>(c); });
    return out;
}

auto contains(std::span<const std::byte> hay, std::span<const std::byte> needle) -> bool {
    return !std::ranges::search(hay, needle).empty();
}

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-blkrole-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() { std::filesystem::remove_all(path); }
};

// A transport that records what it serves; flr() is the VMM's open (or the
// L1 host's reset) arriving through it.
class FakeTransport final : public blk::FunctionTransport {
public:
    explicit FakeTransport(GuestRam& ram) : _ram{&ram} {}

    [[nodiscard]] auto memory() -> const vio::GuestMemory& override { return _ram->memory(); }
    [[nodiscard]] auto interrupts() -> vio::InterruptSink& override { return _irq; }
    [[nodiscard]] auto serve(vio::PciFunction& function, std::function<void()> on_flr)
        -> std::expected<void, std::string> override {
        if (fail) {
            return std::unexpected("refused");
        }
        _served = &function;
        _on_flr = std::move(on_flr);
        ++serves;
        return {};
    }

    auto flr() -> void { _on_flr(); }
    [[nodiscard]] auto served() const -> vio::PciFunction* { return _served; }

    bool fail{false};
    unsigned serves{0};

private:
    GuestRam* _ram;
    RecordingInterrupts _irq;
    vio::PciFunction* _served{nullptr};
    std::function<void()> _on_flr;
};

// A guest driver for whatever function a transport serves right now.
class Guest {
public:
    Guest(GuestRam& ram, vio::PciFunction& fn) : _ram{&ram}, _driver{ram, fn} {}

    auto up() -> bool {
        namespace cc = vio::common_cfg;
        std::uint64_t f = 0;
        for (std::uint32_t word = 0; word < 2; ++word) {
            if (!_driver.common_write(cc::device_feature_select, ak::test::width32, word)) {
                return false;
            }
            f |= _driver.common_read(cc::device_feature, ak::test::width32).value_or(0)
                 << (32U * word);
        }
        return _driver.bring_up(f, {queue0});
    }

    // Posts and notifies one request; returns its id.
    auto post(RequestType type, std::uint64_t sector, std::span<const std::byte> out = {},
              std::uint32_t in_len = 0) -> std::size_t {
        std::vector<Buffer> bufs{{.len = blk::header_size, .writable = false}};
        if (!out.empty()) {
            bufs.push_back({.len = static_cast<std::uint32_t>(out.size()), .writable = false});
        }
        if (in_len != 0) {
            bufs.push_back({.len = in_len, .writable = true});
        }
        bufs.push_back({.len = blk::status_size, .writable = true});
        std::vector<vio::Gpa> gpas;
        _driver.post(queue0, bufs, &gpas);
        std::vector<std::byte> hdr;
        ak::wire::Writer w{hdr};
        w.le32(static_cast<std::uint32_t>(type));
        w.le32(0);
        w.le64(sector);
        _ram->put_bytes(gpas[0], hdr);
        if (!out.empty()) {
            _ram->put_bytes(gpas[1], out);
        }
        _ram->put<std::byte>(gpas.back(), status_canary);
        _requests.push_back({.data = in_len != 0 ? gpas[gpas.size() - 2] : 0,
                             .len = in_len,
                             .status = gpas.back()});
        BOOST_REQUIRE(_driver.notify(queue0));
        return _requests.size() - 1;
    }

    [[nodiscard]] auto completed(std::size_t id) const -> bool {
        return id < _driver.used_idx(queue0);
    }
    [[nodiscard]] auto status(std::size_t id) const -> Status {
        return static_cast<Status>(_ram->get<std::byte>(_requests.at(id).status));
    }
    [[nodiscard]] auto data(std::size_t id) const -> std::vector<std::byte> {
        return _ram->bytes(_requests.at(id).data, _requests.at(id).len);
    }

    auto write(std::uint64_t sector, std::span<const std::byte> d) -> Status {
        return status(post(RequestType::out, sector, d));
    }
    auto read(std::uint64_t sector) -> std::vector<std::byte> {
        const auto id = post(RequestType::in, sector, {}, blk::sector_size);
        BOOST_REQUIRE(completed(id));
        BOOST_REQUIRE(status(id) == Status::ok);
        return data(id);
    }
    auto serial() -> std::string {
        const auto id = post(RequestType::get_id, 0, {}, blk::id_bytes);
        const auto raw = data(id);
        std::string s;
        for (const auto b : raw) {
            if (b == std::byte{0}) {
                break;
            }
            s.push_back(static_cast<char>(b));
        }
        return s;
    }

private:
    struct Request {
        vio::Gpa data;
        std::uint32_t len;
        vio::Gpa status;
    };
    GuestRam* _ram;
    VirtioDriver _driver;
    std::vector<Request> _requests;
};

// An object store in memory, for image volumes.
class MemoryStore final : public blk::ObjectStore {
public:
    auto put(const std::string& key, std::vector<std::byte> bytes) -> void {
        const std::scoped_lock lock{_mutex};
        _objects[key] = std::move(bytes);
    }
    auto get_range(std::string_view key, std::uint64_t offset, std::span<std::byte> out,
                   Clock::time_point /*deadline*/)
        -> std::expected<void, blk::FetchError> override {
        const std::scoped_lock lock{_mutex};
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end() || offset > it->second.size() ||
            out.size() > it->second.size() - offset) {
            return std::unexpected(blk::FetchError::not_found);
        }
        std::copy_n(it->second.begin() + static_cast<std::ptrdiff_t>(offset), out.size(),
                    out.begin());
        return {};
    }
    auto get(std::string_view key, std::size_t max_bytes, Clock::time_point /*deadline*/)
        -> std::expected<std::vector<std::byte>, blk::FetchError> override {
        const std::scoped_lock lock{_mutex};
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end()) {
            return std::unexpected(blk::FetchError::not_found);
        }
        if (it->second.size() > max_bytes) {
            return std::unexpected(blk::FetchError::too_large);
        }
        return it->second;
    }

private:
    std::mutex _mutex;
    std::map<std::string, std::vector<std::byte>> _objects;
};

constexpr std::uint16_t image_store_id = 4;
constexpr std::string_view image_prefix = "images";

// A role over two fake transports and a fresh volume directory; with
// `images`, also an image store (in memory) and a chunk cache.
struct Rig {
    TempDir dir;
    GuestRam ram0;
    GuestRam ram1;
    FakeTransport t0{ram0};
    FakeTransport t1{ram1};
    MemoryStore store;
    std::unique_ptr<blk::ChunkCache> cache;
    std::unique_ptr<blk::Fetcher> fetcher;
    std::unique_ptr<blk::BlkRole> role;

    explicit Rig(bool images = false) {
        std::map<std::uint16_t, blk::ImageStore> stores;
        if (images) {
            auto c = blk::ChunkCache::create(dir.path, std::uint64_t{16} << 20U);
            BOOST_REQUIRE(c.has_value());
            cache = std::move(*c);
            fetcher = blk::Fetcher::create(store, {.workers = 2,
                                                   .deadline = std::chrono::milliseconds{2000},
                                                   .attempts = 2,
                                                   .backoff = std::chrono::milliseconds{1},
                                                   .max_queued_prefetch = 8});
            stores[image_store_id] = {
                .store = &store, .fetcher = fetcher.get(), .prefix = std::string{image_prefix}};
        }
        auto r = blk::BlkRole::create({.volume_dir = dir.path,
                                       .num_queues = 1,
                                       .queue_size = ak::test::test_queue_size,
                                       .seg_max = test_seg_max,
                                       .max_transfer_bytes = test_max_transfer,
                                       .budget = ak::test::test_queue_size,
                                       .image_stores = std::move(stores),
                                       .image_cache = cache.get(),
                                       .overlay_dir = {},
                                       .overlay_limit_bytes = 0,
                                       .max_readahead_chunks = 8,
                                       .manifest_deadline = std::chrono::milliseconds{1000},
                                       .clock = {}},
                                      {&t0, &t1});
        BOOST_REQUIRE(r);
        role = std::move(*r);
    }

    // Packs `raw` and publishes it to the store; the image name.
    auto publish(const std::vector<std::byte>& raw,
                 std::optional<blk::XtsKey> image_key = std::nullopt) -> oar::ImageName {
        const int in = ::memfd_create("image", MFD_CLOEXEC);
        const int data = ::memfd_create("data", MFD_CLOEXEC);
        BOOST_REQUIRE(in >= 0 && data >= 0);
        BOOST_REQUIRE(::write(in, raw.data(), raw.size()) == static_cast<ssize_t>(raw.size()));
        blk::PackOptions o{.logical_block_size = blk::sector_size,
                           .chunk_shift = blk::min_chunk_shift,
                           .image_key = image_key,
                           .key_id = {}};
        if (image_key) {
            o.key_id[0] = std::byte{1};
        }
        const auto packed = blk::pack_image(in, raw.size(), data, o);
        BOOST_REQUIRE(packed.has_value());
        std::vector<std::byte> stored(raw.size());
        BOOST_REQUIRE(::pread(data, stored.data(), stored.size(), 0) ==
                      static_cast<ssize_t>(stored.size()));
        ::close(in);
        ::close(data);
        const auto hex = blk::image_name_hex(packed->name);
        store.put(blk::image_manifest_key(image_prefix, hex), packed->manifest_bytes);
        store.put(blk::image_data_key(image_prefix, hex), std::move(stored));
        return packed->name;
    }

    auto create_image(std::uint64_t volume, std::uint64_t owner, const oar::ImageName& name,
                      std::uint16_t store_id = image_store_id) -> oar::Status {
        return role->create_volume({.volume_id = volume,
                                    .owner_vm = owner,
                                    .capacity_sectors = volume_sectors,
                                    .block_size = blk::sector_size,
                                    .wrapped_key = {},
                                    .image_store = store_id,
                                    .image_name = name});
    }

    auto create(std::uint64_t volume, std::uint64_t owner, std::uint8_t fill = wrapped_fill)
        -> oar::Status {
        const std::vector<std::byte> wrapped(wrapped_size, std::byte{fill});
        return role->create_volume({.volume_id = volume,
                                    .owner_vm = owner,
                                    .capacity_sectors = volume_sectors,
                                    .block_size = blk::sector_size,
                                    .wrapped_key = wrapped,
                                    .image_store = 0,
                                    .image_name = {}});
    }
    auto prepare(oar::FunctionNumber fn, std::uint64_t vm, std::uint64_t volume) -> oar::Status {
        return role->prepare_function({.fn = fn,
                                       .type = ak::helm::FunctionType::blk_fn,
                                       .vm_id = vm,
                                       .config = oar::BlkConfig{.volume_id = volume}});
    }
    auto deliver(oar::FunctionNumber fn, std::uint64_t volume) -> oar::Status {
        const auto key = test_key();
        return role->deliver_key({.fn = fn, .volume_id = volume, .key = key});
    }
    auto clean(oar::FunctionNumber fn) -> oar::Status {
        return role->clean_function(
            {.fn = fn, .action = ak::helm::CleaningAction::drop_volume_key});
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(blk_role, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(inventory_and_placeholders) {
    Rig rig;
    auto inv = rig.role->function_inventory();
    BOOST_REQUIRE(inv.has_value());
    BOOST_TEST((inv->role == oar::Role::blk));
    BOOST_REQUIRE(inv->functions.size() == function_count);
    BOOST_TEST(inv->functions[1].fn == fn1);
    BOOST_TEST((inv->functions[1].type == ak::helm::FunctionType::blk_fn));
    // Each transport serves a placeholder from the start: a disk with no
    // key, whose I/O reaches nothing.
    BOOST_REQUIRE(rig.t0.served() != nullptr);
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    BOOST_TEST(rig.role->function(fn0) == nullptr);
    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST((g.write(0, marker()) == Status::ioerr));
    BOOST_TEST(g.serial() == "akv-none");

    BOOST_TEST(rig.role->health().has_value());
    BOOST_TEST((rig.role->map_update({}) == oar::Status::unsupported));
    BOOST_TEST(blk::volume_serial(vol_one) == "akv-0000000000000201");
}

BOOST_AUTO_TEST_CASE(create_writes_the_wrapped_key_and_never_overwrites) {
    Rig rig;
    BOOST_TEST((rig.create(vol_one, vm_one) == oar::Status::ok));
    const auto path = rig.role->volume_path(vol_one);
    BOOST_TEST(path.filename() == "vol-0000000000000201.akv");
    auto b = blk::FileBackend::open(path);
    BOOST_REQUIRE(b);
    BOOST_TEST((*b)->metadata().owner_vm == vm_one);
    BOOST_TEST((*b)->metadata().capacity_sectors == volume_sectors);
    BOOST_TEST(((*b)->metadata().wrapped_key ==
                std::vector<std::byte>(wrapped_size, std::byte{wrapped_fill})));
    // A second create for the same volume is refused and changes nothing.
    BOOST_TEST((rig.create(vol_one, vm_two, rewrapped_fill) == oar::Status::failed));
    BOOST_TEST(blk::FileBackend::open(path).value()->metadata().owner_vm == vm_one);
}

BOOST_AUTO_TEST_CASE(attach_holds_io_until_the_key_then_encrypts) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    const unsigned serves = rig.t0.serves;
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok));
    BOOST_TEST(rig.t0.serves == serves + 1);
    BOOST_TEST((rig.role->attached(fn0) == vol_one));
    BOOST_REQUIRE(rig.role->function(fn0) != nullptr);
    BOOST_TEST(rig.t0.served() == &rig.role->function(fn0)->pci());
    BOOST_TEST(rig.role->function(fn0)->awaiting_key());

    // The VMM opens the function: an FLR. The wait survives it.
    rig.t0.flr();
    BOOST_TEST(rig.role->function(fn0)->awaiting_key());

    // The guest probes before helm's key arrives: its I/O waits.
    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    const auto plain = marker();
    const auto w = g.post(RequestType::out, marker_sector, plain);
    BOOST_TEST(!rig.role->poll());
    BOOST_TEST(!g.completed(w));

    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::ok));
    static_cast<void>(rig.role->poll());
    BOOST_REQUIRE(g.completed(w));
    BOOST_TEST((g.status(w) == Status::ok));
    BOOST_TEST(g.read(marker_sector) == plain, boost::test_tools::per_element());
    BOOST_TEST(g.serial() == blk::volume_serial(vol_one));

    // Only ciphertext reaches the file, and never the key.
    const auto bytes = file_bytes(rig.role->volume_path(vol_one));
    BOOST_TEST(!contains(bytes, plain));
    const auto key = test_key();
    BOOST_TEST(!contains(bytes, key));
}

BOOST_AUTO_TEST_CASE(prepare_and_key_rules) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.create(vol_two, vm_two) == oar::Status::ok);

    BOOST_TEST((rig.prepare(7, vm_one, vol_one) == oar::Status::unknown_function));
    BOOST_TEST(
        (rig.role->prepare_function({.fn = fn0,
                                     .type = ak::helm::FunctionType::nic_vf,
                                     .vm_id = vm_one,
                                     .config = oar::NicConfig{}}) == oar::Status::wrong_type));
    // Not the owner, or no such volume: refused, nothing attached.
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_one) == oar::Status::failed));
    BOOST_TEST((rig.prepare(fn0, vm_one, 0x999) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    // A key for a function with nothing prepared, or for another volume.
    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::busy));
    BOOST_TEST((rig.deliver(9, vol_one) == oar::Status::unknown_function));

    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_two) == oar::Status::busy));  // fn taken
    BOOST_TEST((rig.prepare(fn1, vm_one, vol_one) == oar::Status::busy));  // volume taken
    BOOST_TEST((rig.deliver(fn0, vol_two) == oar::Status::busy));
    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::ok));
    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::busy));  // drop first
    BOOST_TEST((rig.role->drop_key({.fn = fn0, .volume_id = vol_two}) == oar::Status::busy));
    BOOST_TEST((rig.role->drop_key({.fn = fn0, .volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST(!rig.role->function(fn0)->holds_key());
    BOOST_TEST((rig.role->drop_key({.fn = fn1, .volume_id = vol_one}) == oar::Status::ok));

    // A transport that cannot take the function leaves the placeholder.
    rig.t1.fail = true;
    BOOST_TEST((rig.prepare(fn1, vm_two, vol_two) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn1).has_value());
}

BOOST_AUTO_TEST_CASE(cleaning_closes_the_volume) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    {
        Guest g{rig.ram0, *rig.t0.served()};
        BOOST_REQUIRE(g.up());
        BOOST_TEST((g.write(far_sector, marker()) == Status::ok));
    }
    auto* const attached_pci = rig.t0.served();

    BOOST_TEST(
        (rig.role->clean_function({.fn = fn0, .action = ak::helm::CleaningAction::reset_nic_vf}) ==
         oar::Status::wrong_type));
    BOOST_TEST((rig.clean(fn0) == oar::Status::ok));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    BOOST_TEST(rig.role->function(fn0) == nullptr);
    BOOST_TEST(rig.t0.served() != attached_pci);
    // The placeholder is back: a driver finds a disk it cannot read.
    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    const auto id = g.post(RequestType::in, far_sector, {}, blk::sector_size);
    BOOST_TEST((g.status(id) == Status::ioerr));
    BOOST_TEST((rig.clean(fn0) == oar::Status::ok));  // idempotent
    BOOST_TEST((rig.clean(5) == oar::Status::unknown_function));

    // The volume opens again, for its owner, with its data.
    BOOST_REQUIRE(rig.prepare(fn1, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn1, vol_one) == oar::Status::ok);
    Guest g1{rig.ram1, *rig.t1.served()};
    BOOST_REQUIRE(g1.up());
    BOOST_TEST(g1.read(far_sector) == marker(), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(rewrap_changes_the_owner_on_the_media) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    const std::vector<std::byte> rewrapped(wrapped_size, std::byte{rewrapped_fill});
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    // Not while it is attached.
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = vol_one, .owner_vm = vm_two, .wrapped_key = rewrapped}) ==
                oar::Status::busy));
    BOOST_REQUIRE(rig.clean(fn0) == oar::Status::ok);
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = vol_one, .owner_vm = vm_two, .wrapped_key = rewrapped}) ==
                oar::Status::ok));
    const auto m = blk::FileBackend::open(rig.role->volume_path(vol_one)).value()->metadata();
    BOOST_TEST(m.owner_vm == vm_two);
    BOOST_TEST((m.wrapped_key == rewrapped));
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::failed));
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_one) == oar::Status::ok));
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = 0x999, .owner_vm = vm_two, .wrapped_key = rewrapped}) ==
                oar::Status::failed));
}

BOOST_AUTO_TEST_CASE(delete_erases_even_an_attached_volume) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    const auto path = rig.role->volume_path(vol_one);
    BOOST_REQUIRE(std::filesystem::exists(path));

    // DESTROY_VM without persist_volumes: helm deletes before the function
    // is cleaned. The role lets go of it, then erases.
    BOOST_TEST((rig.role->delete_volume({.volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST(!std::filesystem::exists(path));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    // A retried delete is not an error.
    BOOST_TEST((rig.role->delete_volume({.volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST((rig.clean(fn0) == oar::Status::ok));
}

// helm's real KeyStore and OarLink against the role over a socket pair:
// the wrapped key helm keeps is the one on the media, and the unwrapped key
// helm delivers is the one the data is encrypted with.
BOOST_AUTO_TEST_CASE(helm_drives_the_role_over_the_sideband) {
    Rig rig;
    auto se = ak::helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se);
    ak::helm::KeyStore keys{*se};
    BOOST_REQUIRE(keys.create_vm_key(vm_one));
    BOOST_REQUIRE(keys.create_volume_key(vol_one, vm_one));
    const auto wrapped = keys.find_volume_key(vol_one).value();

    auto pair = ak::helm::SocketBinding::make_pair();
    BOOST_REQUIRE(pair);
    ak::helm::OarLink link{*pair->first, {.address = helm_side, .timeout = link_timeout}};
    ak::helm::OarEndpoint endpoint{*pair->second, {.address = helm_side.reversed()}};
    {
        const std::jthread server{[&](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                auto r = endpoint.serve_one(*rig.role, serve_poll);
                if (!r && r.error() != ak::helm::BindingError::timed_out) {
                    return;
                }
            }
        }};
        BOOST_TEST(link.function_inventory().value().functions.size() == function_count);
        BOOST_TEST(link.create_volume({.volume_id = vol_one,
                                       .owner_vm = vm_one,
                                       .capacity_sectors = volume_sectors,
                                       .block_size = blk::sector_size,
                                       .wrapped_key = wrapped.key.bytes()})
                       .has_value());
        BOOST_TEST(link.prepare_function({.fn = fn1,
                                          .type = ak::helm::FunctionType::blk_fn,
                                          .vm_id = vm_one,
                                          .config = oar::BlkConfig{.volume_id = vol_one}})
                       .has_value());
        auto key = keys.unwrap_volume_key(vol_one, vm_one);
        BOOST_REQUIRE(key);
        BOOST_TEST(link.deliver_key(fn1, vol_one, std::move(*key)).has_value());
    }
    // The media holds exactly helm's wrapped blob.
    const auto m = blk::FileBackend::open(rig.role->volume_path(vol_one)).value()->metadata();
    BOOST_TEST(std::ranges::equal(m.wrapped_key, wrapped.key.bytes()));

    Guest g{rig.ram1, *rig.t1.served()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST((g.write(marker_sector, marker()) == Status::ok));
    BOOST_TEST(g.read(marker_sector) == marker(), boost::test_tools::per_element());
    BOOST_TEST(!contains(file_bytes(rig.role->volume_path(vol_one)), marker()));
}

// ---- image volumes (task 13) ---------------------------------------------

// A 96 KiB image (one full 64 KiB chunk and a 32 KiB tail) of numbered
// sectors, the marker at marker_sector; the 128 KiB volume reads zeros past it.
constexpr std::uint64_t image_sectors = 192;

auto image_raw() -> std::vector<std::byte> {
    std::vector<std::byte> raw(image_sectors * blk::sector_size);
    for (std::size_t i = 0; i < raw.size(); ++i) {
        raw[i] = static_cast<std::byte>((i / blk::sector_size) + 1);
    }
    const auto m = marker();
    std::ranges::copy(m,
                      raw.begin() + static_cast<std::ptrdiff_t>(marker_sector * blk::sector_size));
    return raw;
}

auto sector_of(const std::vector<std::byte>& raw, std::uint64_t sector) -> std::vector<std::byte> {
    const auto from = static_cast<std::ptrdiff_t>(sector * blk::sector_size);
    return {raw.begin() + from, raw.begin() + from + static_cast<std::ptrdiff_t>(blk::sector_size)};
}

BOOST_AUTO_TEST_CASE(image_volume_create_writes_only_a_header) {
    Rig rig{true};
    const auto name = rig.publish(image_raw());
    BOOST_TEST((rig.create_image(vol_one, vm_one, name) == oar::Status::ok));
    const auto path = rig.role->volume_path(vol_one);
    BOOST_TEST(std::filesystem::file_size(path) == blk::metadata_block_size);
    const auto m = blk::FileBackend::read_metadata(path);
    BOOST_REQUIRE(m.has_value());
    BOOST_REQUIRE(m->image.has_value());
    BOOST_TEST(m->image->store_id == image_store_id);
    BOOST_TEST((m->image->name == name));
    BOOST_TEST(m->wrapped_key.empty());
    BOOST_TEST((rig.create_image(vol_one, vm_one, name) == oar::Status::failed));  // exists
    // A store the role does not know, or a role with no image stores.
    BOOST_TEST((rig.create_image(vol_two, vm_one, name, 9) == oar::Status::unsupported));
    Rig plain;
    BOOST_TEST((plain.create_image(vol_two, vm_one, name) == oar::Status::unsupported));
    // Image volumes cannot be rewrapped yet (no key to rewrap); delete works.
    const std::vector<std::byte> wrapped(wrapped_size, std::byte{wrapped_fill});
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = vol_one, .owner_vm = vm_two, .wrapped_key = wrapped}) ==
                oar::Status::failed));
    BOOST_TEST((rig.role->delete_volume({.volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST(!std::filesystem::exists(path));
}

BOOST_AUTO_TEST_CASE(image_volume_serves_the_image_and_forgets_writes) {
    Rig rig{true};
    const auto raw = image_raw();
    const auto name = rig.publish(raw);
    BOOST_REQUIRE(rig.create_image(vol_one, vm_one, name) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_one) == oar::Status::failed));  // not the owner
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    rig.t0.flr();  // the VMM opens the function
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);

    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST(g.read(marker_sector) == marker(), boost::test_tools::per_element());
    BOOST_TEST(g.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
    BOOST_TEST(g.read(far_sector) == std::vector<std::byte>(blk::sector_size),
               boost::test_tools::per_element());  // past the image: zeros
    BOOST_TEST(g.serial() == blk::volume_serial(vol_one));

    // Writes land in the overlay and read back...
    const std::vector<std::byte> mine(blk::sector_size, std::byte{0xEE});
    BOOST_TEST((g.write(3, mine) == Status::ok));
    BOOST_TEST((g.write(far_sector, mine) == Status::ok));
    BOOST_TEST(g.read(3) == mine, boost::test_tools::per_element());
    BOOST_TEST(g.read(far_sector) == mine, boost::test_tools::per_element());
    // ...never reaching the object store or the volume file.
    const auto stored =
        rig.store.get(blk::image_data_key(image_prefix, blk::image_name_hex(name)), 1U << 20U, {});
    BOOST_TEST(!contains(*stored, mine));
    BOOST_TEST(std::filesystem::file_size(rig.role->volume_path(vol_one)) ==
               blk::metadata_block_size);

    // An FLR takes the key and the overlay: with a new key the image is as
    // it was.
    rig.t0.flr();
    BOOST_TEST(!rig.role->function(fn0)->holds_key());
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    Guest g2{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g2.up());
    BOOST_TEST(g2.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
    BOOST_TEST(g2.read(far_sector) == std::vector<std::byte>(blk::sector_size),
               boost::test_tools::per_element());

    // So does drop_key, and so does detach (cleaning) and a new attachment.
    BOOST_TEST((g2.write(3, mine) == Status::ok));
    BOOST_TEST((rig.role->drop_key({.fn = fn0, .volume_id = vol_one}) == oar::Status::ok));
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    BOOST_TEST(g2.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
    BOOST_TEST((g2.write(3, mine) == Status::ok));
    BOOST_REQUIRE(rig.clean(fn0) == oar::Status::ok);
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    BOOST_REQUIRE(rig.prepare(fn1, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn1, vol_one) == oar::Status::ok);
    Guest g3{rig.ram1, *rig.t1.served()};
    BOOST_REQUIRE(g3.up());
    BOOST_TEST(g3.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(image_volume_refuses_a_missing_or_wrong_image) {
    Rig rig{true};
    const auto name = rig.publish(image_raw());
    // Named but never published.
    oar::ImageName missing = name;
    missing[0] ^= std::byte{1};
    BOOST_REQUIRE(rig.create_image(vol_one, vm_one, missing) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn0).has_value());

    // The store answers with another image's manifest under this name.
    auto other = image_raw();
    other[0] = std::byte{0x77};
    const auto other_name = rig.publish(other);
    const auto other_manifest = rig.store.get(
        blk::image_manifest_key(image_prefix, blk::image_name_hex(other_name)), 1U << 26U, {});
    rig.store.put(blk::image_manifest_key(image_prefix, blk::image_name_hex(missing)),
                  *other_manifest);
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::failed));

    // An encrypted image waits for helm to deliver its key (task 15).
    const auto key = test_key();
    const auto secret = rig.publish(image_raw(), blk::XtsKey{key});
    BOOST_REQUIRE(rig.create_image(vol_two, vm_one, secret) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_two) == oar::Status::failed));

    // The image is fine but the volume is smaller than it.
    BOOST_REQUIRE(rig.role->create_volume({.volume_id = 0x203,
                                           .owner_vm = vm_one,
                                           .capacity_sectors = image_sectors - 8,
                                           .block_size = blk::sector_size,
                                           .wrapped_key = {},
                                           .image_store = image_store_id,
                                           .image_name = name}) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_one, 0x203) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
