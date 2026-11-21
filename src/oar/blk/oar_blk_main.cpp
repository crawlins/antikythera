// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-oar-blk: the storage role for harbor (.kiro/specs/oar-blk-data-plane/
// task 6). virtio-blk functions served over vfio-user, volumes as files,
// driven by helm over its sideband socket.
//
//   ak-oar-blk --volumes DIR --sideband PATH --addr A --helm-addr A
//              --eid E --helm-eid E --function SOCKET [--function SOCKET ...]
//              [--queues N]
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
                 "usage: {} {} DIR {} PATH {} A {} A {} E {} E {} SOCKET [{} SOCKET ...] [{} N]",
                 log_name, arg_volumes, arg_sideband, arg_addr, arg_helm_addr, arg_eid,
                 arg_helm_eid, arg_function, arg_function, arg_queues);
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
        } else {
            return std::nullopt;
        }
    }
    if (o.volumes.empty() || o.sideband.empty() || o.functions.empty() || !o.addr || !o.helm_addr ||
        !o.eid || !o.helm_eid) {
        return std::nullopt;
    }
    return o;
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
    auto role =
        blk::BlkRole::create({.volume_dir = opts->volumes,
                              .num_queues = static_cast<std::uint16_t>(opts->queues),
                              .queue_size = blk::BlkParams{}.queue_size,
                              .seg_max = blk::VolumeGeometry{}.seg_max,
                              .max_transfer_bytes = blk::VolumeGeometry{}.max_transfer_bytes,
                              .budget = blk::BlkParams{}.budget,
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
    std::println(stderr, "{}: {} function(s), volumes in {}, sideband {}", log_name,
                 transports.size(), opts->volumes, opts->sideband);

    bool more = false;
    for (;;) {
        // [0] the sideband (or its listener), then one entry per function,
        // then the backends' wake descriptors: a backend completing later
        // than its submit wakes the loop, and poll() below runs it.
        std::vector<pollfd> fds(1 + transports.size());
        fds[0] = {
            .fd = sideband ? sideband->fd() : (*listener)->fd(), .events = POLLIN, .revents = 0};
        for (std::size_t i = 0; i < transports.size(); ++i) {
            fds[i + 1] = {.fd = transports[i]->binding().poll_fd(), .events = POLLIN, .revents = 0};
        }
        for (const int fd : (*role)->wake_fds()) {
            fds.push_back({.fd = fd, .events = POLLIN, .revents = 0});
        }
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
