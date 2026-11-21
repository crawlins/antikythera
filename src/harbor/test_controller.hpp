// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// harbor's test controller (.kiro/specs/controller-interface/ task 5): a
// stand-in for kythira's EC2 module that signs commands and mapping
// updates and drives one server's helm over the ControllerLink, so harbor
// phases 3-5 run before kythira's module exists.
//
// Three pieces, each usable alone:
//
//   Signer          pure Ed25519 (RFC 8032) over the exact bytes hull and
//                   oar-net verify: slot bytes [0x00, 0xC0), and a
//                   MapUpdate's every byte before its signature.
//   parse_line      the script language below, one action per line.
//   TestController  the mTLS server side of the ControllerLink: accepts
//                   helm, acknowledges its reports, sends signed
//                   envelopes with per-server sequence numbers that
//                   resume after the inventory's last_command_seq
//                   (Requirement 2.3), and waits for outcomes.
//
// Script language (blank lines and text after '#' are ignored; numbers
// are decimal or 0x-prefixed hex):
//
//   create-vm VM VCPUS MEMORY_MIB
//   destroy-vm VM [persist]
//   list-vms
//   vm-status VM
//   attach-device VM SLOT nic FN VNI NIC_ID MAC   e.g. 1 2 nic 0 0x10 0x10 02:00:00:00:00:10
//   attach-device VM SLOT gpu|gpu-vf FN
//   detach-device VM SLOT nic|gpu|gpu-vf FN TIMEOUT_S force|destroy-vm
//   create-volume VOLUME OWNER_VM SIZE_GIB [STORE IMAGE_NAME]
//                        with STORE and the image's 64-hex-digit name: an
//                        image volume (oar-blk Requirement 8)
//   delete-volume VOLUME
//   attach-volume VOLUME VM SLOT FN
//   detach-volume VOLUME VM SLOT FN TIMEOUT_S force|destroy-vm
//   rewrap-volume VOLUME FROM_VM TO_VM
//   create-network VNI
//   delete-network VNI
//   map-update VNI VERSION [NIC,MAC,VTEP[,GUEST_IP ...] ...]
//                        e.g. 0x10,02:00:00:00:00:10,fd00::1,10.0.0.5,fd12::5
//                        (guest IPs are what the ARP/ND proxy answers for)
//   group-policy VNI VERSION drop
//   group-policy VNI VERSION multicast RATE_FRAMES BURST_FRAMES RATE_BYTES BURST_BYTES
//                MAX_REMOTE_VTEPS [MAX_GROUPS_PER_NIC]
//                        the VPC's broadcast/multicast policy (oar-net Requirement 10)
//   expect STATUS        the last command's outcome must be STATUS
//                        (ok, accepted, bad_signature, stale_sequence, wrong_server, ...)
//   wait KIND            wait for a report of KIND (inventory, command_outcome,
//                        pool_state, vm_exited, map_applied, host_fault,
//                        group_usage)
//
// The RFC 8032 test keys are for harbor only; a real host image never
// compiles them in.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "helm/mailbox.hpp"
#include "proto/envelope.hpp"
#include "proto/link.hpp"
#include "proto/group_policy.hpp"
#include "proto/map_update.hpp"
#include "proto/report.hpp"
#include "tls/tls.hpp"

namespace ak::harbor {

inline constexpr std::size_t ed25519_secret_size = 32;

class Signer {
public:
    // A PEM private key (`openssl genpkey -algorithm ed25519`).
    [[nodiscard]] static auto from_pem(const std::string& pem) -> std::optional<Signer>;
    // A raw 32-byte Ed25519 secret, as RFC 8032 lists its test keys.
    [[nodiscard]] static auto from_raw(std::span<const std::byte, ed25519_secret_size> secret)
        -> std::optional<Signer>;

    Signer(Signer&&) noexcept;
    auto operator=(Signer&&) noexcept -> Signer&;
    Signer(const Signer&) = delete;
    auto operator=(const Signer&) -> Signer& = delete;
    ~Signer();

    [[nodiscard]] auto sign(std::span<const std::byte> message) const
        -> std::optional<proto::Ed25519Signature>;

    // A signed command slot for `body`, wrapped in an envelope.
    [[nodiscard]] auto envelope(std::uint64_t server_id, proto::KeyId key_id, std::uint64_t seq,
                                const helm::mailbox::Body& body) const
        -> std::optional<proto::EnvelopeBytes>;

    // `update` encoded and signed (its signature field is ignored).
    [[nodiscard]] auto group_policy(const proto::GroupPolicy& policy) const
        -> std::optional<std::vector<std::byte>>;
    [[nodiscard]] auto map_update(const proto::MapUpdate& update) const
        -> std::optional<std::vector<std::byte>>;

private:
    struct Impl;
    explicit Signer(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> _impl;
};

// ---- Script ---------------------------------------------------------------

struct SendCommand {
    helm::mailbox::Body body;
};
struct SendMapUpdate {
    std::uint32_t vni{0};
    std::uint64_t map_version{0};
    std::vector<proto::MapEntry> entries;
    std::vector<proto::GuestIpv4> ipv4;
    std::vector<proto::GuestIpv6> ipv6;
};
struct SendGroupPolicy {
    std::uint32_t vni{0};
    std::uint64_t policy_version{0};
    proto::GroupMode mode{proto::GroupMode::drop};
    std::uint32_t rate_frames{0};
    std::uint32_t burst_frames{0};
    std::uint64_t rate_bytes{0};
    std::uint64_t burst_bytes{0};
    std::uint32_t max_remote_vteps{0};
    std::uint16_t max_groups_per_nic{0};
};
struct ExpectOutcome {
    proto::CommandStatus status{proto::CommandStatus::ok};
};
struct WaitReport {
    proto::ReportKind kind{proto::ReportKind::inventory};
};

using Action = std::variant<SendCommand, SendMapUpdate, SendGroupPolicy, ExpectOutcome, WaitReport>;

// One script line: an action, nothing (blank or comment), or a message
// saying what is wrong with it.
[[nodiscard]] auto parse_line(std::string_view line)
    -> std::expected<std::optional<Action>, std::string>;

[[nodiscard]] auto to_string(const proto::Report& report) -> std::string;

// ---- Controller -----------------------------------------------------------

struct ControllerOptions {
    tls::Config tls;  // role server; ca_pem is the CA that issues server certs
    std::uint64_t server_id{0};
    proto::KeyId key_id{0};
    std::chrono::milliseconds timeout{std::chrono::seconds{30}};
    // Called with every report as it arrives (e.g. to print it).
    std::function<void(const proto::Report&)> on_report;
};

class TestController {
public:
    [[nodiscard]] static auto create(ControllerOptions options, Signer signer)
        -> std::expected<TestController, std::string>;

    // Waits for helm to connect and register (hello, then its inventory).
    [[nodiscard]] auto accept(tls::Listener& listener) -> std::expected<void, std::string>;

    // Runs one action. Errors name what failed.
    [[nodiscard]] auto run(const Action& action) -> std::expected<void, std::string>;

    // The sequence number the next command gets.
    [[nodiscard]] auto next_seq() const noexcept -> std::uint64_t { return _next_seq; }
    [[nodiscard]] auto boot_id() const noexcept -> std::uint64_t { return _boot_id; }
    [[nodiscard]] auto inventory() const noexcept -> const std::optional<proto::Inventory>& {
        return _inventory;
    }

private:
    TestController(ControllerOptions options, Signer signer, tls::Context ctx);

    auto send(proto::RecordType type, std::span<const std::byte> payload)
        -> std::expected<void, std::string>;
    // Reads and handles records until `done` holds or the timeout passes.
    auto pump(const std::function<bool(const proto::Report&)>& done)
        -> std::expected<proto::Report, std::string>;
    auto handle(const proto::Record& rec)
        -> std::expected<std::optional<proto::Report>, std::string>;

    ControllerOptions _options;
    Signer _signer;
    tls::Context _ctx;
    std::optional<tls::Stream> _stream;
    proto::RecordDecoder _decoder;
    std::uint64_t _boot_id{0};
    std::uint64_t _last_report_seq{0};
    std::uint64_t _next_seq{1};
    std::uint64_t _last_command_seq{0};
    std::optional<proto::Inventory> _inventory;
    std::vector<proto::Report> _backlog;  // reports read but not yet waited for
};

}  // namespace ak::harbor
