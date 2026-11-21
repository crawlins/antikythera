// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-oar-blk: the storage role for harbor (.kiro/specs/oar-blk-data-plane/
// task 6). virtio-blk functions served over vfio-user, volumes as files,
// driven by helm over its sideband socket.
//
//   ak-oar-blk --volumes DIR --sideband PATH --addr A --helm-addr A
//              --eid E --helm-eid E --function SOCKET [--function SOCKET ...]
//              [--queues N]
//              [--image-cache DIR [--image-cache-bytes N] --image-store ID=PATH ...]
//
// Function i is the i-th --function: L0 QEMU attaches to its socket with
// vfio-user-pci when the L1 host boots, and the L1 host binds it to
// vfio-pci for hull to hand to an L2 guest. Between attachments it is an
// empty disk with no key (BlkRole's placeholder).
//
// The sideband is helm's: this process listens on PATH (SOCK_SEQPACKET;
// the path must not exist, or be a stale socket, which is removed) and
// serves one helm connection at a time with BlkRole. --addr/--eid are
// this board's bus address and EID, --helm-addr/--helm-eid helm's, as in
// helm's `slot` directive. If helm goes away the process listens again.
//
// Image volumes (task 13): each --image-store names an object store by the
// ID helm's create_volume uses (1..65535) and the file that configures it
// (image_store_config.hpp); a file holding a secret key must not be
// readable by group or others. --image-cache is the directory for the
// chunk cache all image volumes share (one unlinked file per image, so
// nothing survives the process), --image-cache-bytes its budget (default
// 1 GiB). Overlays go in the volume directory, also as unlinked files.
//
// Volume keys arrive only over the sideband and live only in each
// function's locked key slot; the process disables core dumps and ptrace
// before it starts serving.

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <functional>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <poll.h>
#include <sys/stat.h>

#include "helm/oar_link.hpp"
#include "helm/sideband_binding.hpp"
#include "oar/blk/blk_role.hpp"
#include "oar/blk/chunk_cache.hpp"
#include "oar/blk/fetcher.hpp"
#include "oar/blk/image_store_config.hpp"
#include "oar/blk/s3_object_store.hpp"
#include "oar/blk/key_slot.hpp"
#include "oar/vfu/virtio_binding.hpp"

namespace {

namespace blk = ak::oar::blk;
namespace helm = ak::helm;

constexpr std::string_view arg_volumes = "--volumes";
constexpr std::string_view arg_sideband = "--sideband";
constexpr std::string_view arg_addr = "--addr";
constexpr std::string_view arg_helm_addr = "--helm-addr";
constexpr std::string_view arg_eid = "--eid";
constexpr std::string_view arg_helm_eid = "--helm-eid";
constexpr std::string_view arg_function = "--function";
constexpr std::string_view arg_queues = "--queues";
constexpr std::string_view arg_image_cache = "--image-cache";
constexpr std::string_view arg_image_cache_bytes = "--image-cache-bytes";
constexpr std::string_view arg_image_store = "--image-store";
constexpr std::uint64_t default_image_cache_bytes = std::uint64_t{1} << 30U;
constexpr std::uint64_t max_store_id = 0xFFFF;
constexpr mode_t group_other_bits = 077;
constexpr std::string_view log_name = "ak-oar-blk";
constexpr int base_auto = 0;
constexpr int poll_forever = -1;
constexpr int poll_now = 0;
constexpr std::uint64_t max_bus_addr = 0x7F;
constexpr std::uint64_t max_eid = 0xFE;
constexpr std::uint64_t max_queues = 64;
constexpr int exit_usage = 2;
constexpr auto no_wait = std::chrono::milliseconds{0};

auto usage() -> int {
    std::println(stderr,
                 "usage: {} {} DIR {} PATH {} A {} A {} E {} E {} SOCKET [{} SOCKET ...] [{} N]\n"
                 "       [{} DIR [{} N] {} ID=PATH ...]",
                 log_name, arg_volumes, arg_sideband, arg_addr, arg_helm_addr, arg_eid,
                 arg_helm_eid, arg_function, arg_function, arg_queues, arg_image_cache,
                 arg_image_cache_bytes, arg_image_store);
    return exit_usage;
}

auto parse_u64(std::string_view s, std::uint64_t max) -> std::optional<std::uint64_t> {
    const std::string text{s};
    char* end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(text.c_str(), &end, base_auto);
    if (errno != 0 || end == text.c_str() || *end != '\0' || v > max) {
        return std::nullopt;
    }
    return v;
}

// One function's vfio-user context, as BlkRole drives it: bound with the
// placeholder, retargeted to each attachment.
class VfuTransport final : public blk::FunctionTransport {
public:
    explicit VfuTransport(std::unique_ptr<ak::oar::vfu::VirtioBinding> binding)
        : _binding{std::move(binding)} {}

    [[nodiscard]] auto memory() -> const ak::oar::virtio::GuestMemory& override {
        return _binding->memory();
    }
    [[nodiscard]] auto interrupts() -> ak::oar::virtio::InterruptSink& override {
        return *_binding;
    }
    [[nodiscard]] auto serve(ak::oar::virtio::PciFunction& function, std::function<void()> on_flr)
        -> std::expected<void, std::string> override {
        auto ok = _bound ? _binding->retarget(function) : _binding->bind(function);
        if (!ok) {
            return ok;
        }
        _bound = true;
        _binding->set_reset_handler(std::move(on_flr));
        return {};
    }

    [[nodiscard]] auto binding() -> ak::oar::vfu::VirtioBinding& { return *_binding; }
    bool attached{false};

private:
    std::unique_ptr<ak::oar::vfu::VirtioBinding> _binding;
    bool _bound{false};
};

// A stale socket from an earlier run may be removed; anything else at the
// path is left alone and refused by SocketListener::bind.
auto remove_stale_socket(const std::string& path) -> void {
    struct stat st{};
    if (::lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
        std::filesystem::remove(path);
    }
}

struct Options {
    std::string volumes;
    std::string sideband;
    std::vector<std::string> functions;
    std::optional<std::uint64_t> addr;
    std::optional<std::uint64_t> helm_addr;
    std::optional<std::uint64_t> eid;
    std::optional<std::uint64_t> helm_eid;
    std::uint64_t queues{1};
    std::string image_cache;
    std::uint64_t image_cache_bytes{default_image_cache_bytes};
    std::map<std::uint16_t, std::string> image_stores;
};

auto parse(int argc, char** argv) -> std::optional<Options> {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (i + 1 >= argc) {
            return std::nullopt;
        }
        const std::string_view value{argv[++i]};
        if (arg == arg_volumes) {
            o.volumes = value;
        } else if (arg == arg_sideband) {
            o.sideband = value;
        } else if (arg == arg_function) {
            o.functions.emplace_back(value);
        } else if (arg == arg_addr) {
            o.addr = parse_u64(value, max_bus_addr);
        } else if (arg == arg_helm_addr) {
            o.helm_addr = parse_u64(value, max_bus_addr);
        } else if (arg == arg_eid) {
            o.eid = parse_u64(value, max_eid);
        } else if (arg == arg_helm_eid) {
            o.helm_eid = parse_u64(value, max_eid);
        } else if (arg == arg_queues) {
            auto q = parse_u64(value, max_queues);
            if (!q || *q == 0) {
                return std::nullopt;
            }
            o.queues = *q;
        } else if (arg == arg_image_cache) {
            o.image_cache = value;
        } else if (arg == arg_image_cache_bytes) {
            auto n = parse_u64(value, UINT64_MAX);
            if (!n || *n == 0) {
                return std::nullopt;
            }
            o.image_cache_bytes = *n;
        } else if (arg == arg_image_store) {
            const auto eq = value.find('=');
            const auto id = parse_u64(value.substr(0, eq), max_store_id);
            if (eq == std::string_view::npos || !id || *id == 0 || eq + 1 == value.size() ||
                !o.image_stores.emplace(static_cast<std::uint16_t>(*id), value.substr(eq + 1))
                     .second) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }
    if (o.volumes.empty() || o.sideband.empty() || o.functions.empty() || !o.addr || !o.helm_addr ||
        !o.eid || !o.helm_eid || o.image_stores.empty() != o.image_cache.empty()) {
        return std::nullopt;
    }
    return o;
}

// One configured image store and the fetcher in front of it.
struct LoadedStore {
    std::unique_ptr<blk::S3ObjectStore> store;
    std::unique_ptr<blk::Fetcher> fetcher;
    std::string prefix;
};

auto load_store(const std::string& path) -> std::expected<LoadedStore, std::string> {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) {
        return std::unexpected(std::format("{}: {}", path, std::strerror(errno)));
    }
    std::ifstream in{path};
    if (!in) {
        return std::unexpected(std::format("{}: cannot read", path));
    }
    const std::string text{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    auto cfg = blk::parse_image_store_config(text);
    if (!cfg) {
        return std::unexpected(std::format("{}: {}", path, cfg.error()));
    }
    if (cfg->s3.credentials && (st.st_mode & group_other_bits) != 0) {
        return std::unexpected(
            std::format("{}: holds a secret key but is readable by group or others", path));
    }
    auto store = blk::S3ObjectStore::create(std::move(cfg->s3));
    if (!store) {
        return std::unexpected(std::format("{}: {}", path, blk::to_string(store.error())));
    }
    LoadedStore out{.store = std::move(*store), .fetcher = nullptr, .prefix = cfg->prefix};
    out.fetcher = blk::Fetcher::create(*out.store, blk::FetcherConfig{});
    return out;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const auto opts = parse(argc, argv);
    if (!opts) {
        return usage();
    }
    if (auto hardened = blk::harden_process(); !hardened) {
        std::println(stderr, "{}: {}", log_name, blk::to_string(hardened.error()));
        return EXIT_FAILURE;
    }

    std::vector<std::unique_ptr<VfuTransport>> transports;
    std::vector<blk::FunctionTransport*> raw;
    for (std::size_t i = 0; i < opts->functions.size(); ++i) {
        auto b = ak::oar::vfu::VirtioBinding::create(opts->functions[i],
                                                     std::format("{}[fn {}]", log_name, i));
        if (!b) {
            std::println(stderr, "{}: function {}: {}", log_name, i, b.error());
            return EXIT_FAILURE;
        }
        transports.push_back(std::make_unique<VfuTransport>(std::move(*b)));
        raw.push_back(transports.back().get());
    }
    // Image stores, their fetchers and the cache outlive the role.
    std::map<std::uint16_t, LoadedStore> stores;
    std::map<std::uint16_t, blk::ImageStore> image_stores;
    std::unique_ptr<blk::ChunkCache> cache;
    if (!opts->image_cache.empty()) {
        auto c = blk::ChunkCache::create(opts->image_cache, opts->image_cache_bytes);
        if (!c) {
            std::println(stderr, "{}: image cache {}: {}", log_name, opts->image_cache,
                         std::strerror(c.error()));
            return EXIT_FAILURE;
        }
        cache = std::move(*c);
        for (const auto& [id, path] : opts->image_stores) {
            auto loaded = load_store(path);
            if (!loaded) {
                std::println(stderr, "{}: image store {}: {}", log_name, id, loaded.error());
                return EXIT_FAILURE;
            }
            auto& l = stores.emplace(id, std::move(*loaded)).first->second;
            image_stores[id] = {
                .store = l.store.get(), .fetcher = l.fetcher.get(), .prefix = l.prefix};
        }
    }
    const blk::RoleConfig defaults;
    auto role =
        blk::BlkRole::create({.volume_dir = opts->volumes,
                              .num_queues = static_cast<std::uint16_t>(opts->queues),
                              .queue_size = blk::BlkParams{}.queue_size,
                              .seg_max = blk::VolumeGeometry{}.seg_max,
                              .max_transfer_bytes = blk::VolumeGeometry{}.max_transfer_bytes,
                              .budget = blk::BlkParams{}.budget,
                              .image_stores = std::move(image_stores),
                              .image_cache = cache.get(),
                              .overlay_dir = {},
                              .overlay_limit_bytes = 0,
                              .max_readahead_chunks = defaults.max_readahead_chunks,
                              .manifest_deadline = defaults.manifest_deadline,
                              .clock = {}},
                             raw);
    if (!role) {
        std::println(stderr, "{}: {}", log_name, role.error());
        return EXIT_FAILURE;
    }

    remove_stale_socket(opts->sideband);
    auto listener = helm::SocketListener::bind(opts->sideband);
    if (!listener) {
        std::println(stderr, "{}: listen on {}: {}", log_name, opts->sideband,
                     helm::to_string(listener.error()));
        return EXIT_FAILURE;
    }
    const helm::LinkConfig link{
        .address = {.local_addr = static_cast<std::uint8_t>(*opts->addr),
                    .peer_addr = static_cast<std::uint8_t>(*opts->helm_addr),
                    .local_eid = static_cast<std::uint8_t>(*opts->eid),
                    .peer_eid = static_cast<std::uint8_t>(*opts->helm_eid)},
        .mtu = helm::mctp::baseline_mtu,
        .timeout = {}};
    std::unique_ptr<helm::SocketBinding> sideband;
    std::unique_ptr<helm::OarEndpoint> endpoint;
    std::println(stderr, "{}: {} function(s), volumes in {}, {} image store(s), sideband {}",
                 log_name, transports.size(), opts->volumes, stores.size(), opts->sideband);

    bool more = false;
    for (;;) {
        // [0] the sideband (or its listener), then one entry per function,
        // then the role's waker (an image chunk arrived for a parked read;
        // the role->poll() below serves it).
        std::vector<pollfd> fds(2 + transports.size());
        fds[0] = {
            .fd = sideband ? sideband->fd() : (*listener)->fd(), .events = POLLIN, .revents = 0};
        for (std::size_t i = 0; i < transports.size(); ++i) {
            fds[i + 1] = {.fd = transports[i]->binding().poll_fd(), .events = POLLIN, .revents = 0};
        }
        fds.back() = {.fd = (*role)->wake_fd(), .events = POLLIN, .revents = 0};
        if (::poll(fds.data(), fds.size(), more ? poll_now : poll_forever) < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::println(stderr, "{}: poll: {}", log_name, std::strerror(errno));
            return EXIT_FAILURE;
        }

        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            if (!sideband) {
                auto accepted = (*listener)->accept(no_wait);
                if (accepted) {
                    sideband = std::move(*accepted);
                    endpoint = std::make_unique<helm::OarEndpoint>(*sideband, link);
                    std::println(stderr, "{}: helm connected", log_name);
                }
            } else {
                // Drain what arrived; each call takes one packet.
                for (;;) {
                    auto r = endpoint->serve_one(**role, no_wait);
                    if (r) {
                        continue;
                    }
                    if (r.error() != helm::BindingError::timed_out) {
                        std::println(stderr, "{}: helm sideband: {}", log_name,
                                     helm::to_string(r.error()));
                        endpoint.reset();
                        sideband.reset();
                    }
                    break;
                }
            }
        }

        for (std::size_t i = 0; i < transports.size(); ++i) {
            VfuTransport& t = *transports[i];
            if (!t.attached) {
                auto a = t.binding().attach();
                if (!a) {
                    std::println(stderr, "{}: function {}: {}", log_name, i, a.error());
                    return EXIT_FAILURE;
                }
                t.attached = *a;
                continue;
            }
            if ((fds[i + 1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
                auto r = t.binding().run();
                if (!r) {
                    std::println(stderr, "{}: function {}: {}", log_name, i, r.error());
                    return EXIT_FAILURE;
                }
                t.attached = *r;
            }
        }
        more = (*role)->poll();
    }
}
