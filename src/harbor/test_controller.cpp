// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "harbor/test_controller.hpp"

#include <arpa/inet.h>
#include <poll.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <climits>
#include <cstring>
#include <sstream>
#include <utility>

namespace ak::harbor {

namespace mb = helm::mailbox;

// ---- Signer ---------------------------------------------------------------

struct Signer::Impl {
    struct PkeyFree {
        auto operator()(EVP_PKEY* p) const noexcept -> void { EVP_PKEY_free(p); }
    };
    std::unique_ptr<EVP_PKEY, PkeyFree> pkey;
};

Signer::Signer(std::unique_ptr<Impl> impl) noexcept : _impl{std::move(impl)} {}
Signer::Signer(Signer&&) noexcept = default;
auto Signer::operator=(Signer&&) noexcept -> Signer& = default;
Signer::~Signer() = default;

auto Signer::from_pem(const std::string& pem) -> std::optional<Signer> {
    if (pem.size() > static_cast<std::size_t>(INT_MAX)) {
        return std::nullopt;
    }
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio{
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
    auto impl = std::make_unique<Impl>();
    if (bio) {
        impl->pkey.reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    }
    ERR_clear_error();
    if (!impl->pkey || EVP_PKEY_get_id(impl->pkey.get()) != EVP_PKEY_ED25519) {
        return std::nullopt;
    }
    return Signer{std::move(impl)};
}

auto Signer::from_raw(std::span<const std::byte, ed25519_secret_size> secret)
    -> std::optional<Signer> {
    auto impl = std::make_unique<Impl>();
    impl->pkey.reset(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(secret.data()),
        secret.size()));
    ERR_clear_error();
    if (!impl->pkey) {
        return std::nullopt;
    }
    return Signer{std::move(impl)};
}

auto Signer::sign(std::span<const std::byte> message) const
    -> std::optional<proto::Ed25519Signature> {
    proto::Ed25519Signature sig{};
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(),
                                                                      &EVP_MD_CTX_free};
    std::size_t len = sig.size();
    const bool ok =
        ctx && EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, _impl->pkey.get()) == 1 &&
        EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(sig.data()), &len,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) == 1 &&
        len == sig.size();
    ERR_clear_error();
    if (!ok) {
        return std::nullopt;
    }
    return sig;
}

auto Signer::envelope(std::uint64_t server_id, proto::KeyId key_id, std::uint64_t seq,
                      const mb::Body& body) const -> std::optional<proto::EnvelopeBytes> {
    const auto bytes = mb::encode_body(body);
    const mb::Header header{.type = mb::type_of(body),
                            .seq = seq,
                            .body_len = static_cast<std::uint16_t>(bytes.size()),
                            .key_id = key_id,
                            .server_id = server_id};
    const std::array<std::byte, mb::signature_size> blank{};
    auto slot = mb::encode(header, bytes, blank);
    if (!slot) {
        return std::nullopt;
    }
    const auto sig = sign(proto::slot_signed_bytes(*slot));
    if (!sig) {
        return std::nullopt;
    }
    std::ranges::copy(*sig, slot->begin() + mb::signature_offset);
    auto env = proto::encode_envelope({.server_id = server_id, .key_id = key_id, .slot = *slot});
    if (!env) {
        return std::nullopt;
    }
    return *env;
}

auto Signer::map_update(const proto::MapUpdate& update) const
    -> std::optional<std::vector<std::byte>> {
    auto frame = proto::encode_map_update(update);
    if (!frame) {
        return std::nullopt;
    }
    const auto sig = sign(proto::map_update_signed_bytes(*frame));
    if (!sig) {
        return std::nullopt;
    }
    proto::set_map_update_signature(*frame, *sig);
    return *frame;
}

auto Signer::group_policy(const proto::GroupPolicy& policy) const
    -> std::optional<std::vector<std::byte>> {
    auto frame = proto::encode_group_policy(policy);
    if (!frame) {
        return std::nullopt;
    }
    const auto sig = sign(proto::group_policy_signed_bytes(*frame));
    if (!sig) {
        return std::nullopt;
    }
    proto::set_group_policy_signature(*frame, *sig);
    return *frame;
}

// ---- Script ---------------------------------------------------------------

namespace {

auto split(std::string_view line) -> std::vector<std::string_view> {
    if (auto hash = line.find('#'); hash != std::string_view::npos) {
        line = line.substr(0, hash);
    }
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) {
            ++i;
        }
        const std::size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') {
            ++i;
        }
        if (i > start) {
            out.push_back(line.substr(start, i - start));
        }
    }
    return out;
}

template<std::unsigned_integral T>
auto number(std::string_view s, const char* what) -> std::expected<T, std::string> {
    int base = 10;
    if (s.starts_with("0x") || s.starts_with("0X")) {
        s.remove_prefix(2);
        base = 16;
    }
    T v{};
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
    if (s.empty() || ec != std::errc{} || end != s.data() + s.size()) {
        return std::unexpected(std::string{"bad "} + what);
    }
    return v;
}

auto device_type(std::string_view s) -> std::expected<mb::DeviceType, std::string> {
    if (s == "nic") {
        return mb::DeviceType::nic_vf;
    }
    if (s == "gpu") {
        return mb::DeviceType::gpu_whole;
    }
    if (s == "gpu-vf") {
        return mb::DeviceType::gpu_vf;
    }
    return std::unexpected("device type must be nic, gpu or gpu-vf");
}

auto policy(std::string_view s) -> std::expected<mb::DetachPolicy, std::string> {
    if (s == "force") {
        return mb::DetachPolicy::force;
    }
    if (s == "destroy-vm") {
        return mb::DetachPolicy::destroy_vm;
    }
    return std::unexpected("policy must be force or destroy-vm");
}

auto mac(std::string_view s) -> std::expected<proto::Mac, std::string> {
    proto::Mac out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const auto part = s.substr(i * 3, 2);
        const bool sep_ok = i + 1 == out.size() ? s.size() == (i * 3) + 2
                                                : s.size() > (i * 3) + 2 && s[(i * 3) + 2] == ':';
        std::uint8_t v = 0;
        const auto [end, ec] = std::from_chars(part.data(), part.data() + part.size(), v, 16);
        if (part.size() != 2 || ec != std::errc{} || end != part.data() + 2 || !sep_ok) {
            return std::unexpected("bad MAC (want 02:00:00:00:00:01)");
        }
        out[i] = std::byte{v};
    }
    return out;
}

auto image_name(std::string_view s) -> std::expected<mb::ImageName, std::string> {
    mb::ImageName out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const auto part = s.substr(i * 2, 2);
        std::uint8_t v = 0;
        const auto [end, ec] = std::from_chars(part.data(), part.data() + part.size(), v, 16);
        if (part.size() != 2 || ec != std::errc{} || end != part.data() + 2) {
            return std::unexpected("bad image name (want 64 hex digits)");
        }
        out[i] = std::byte{v};
    }
    if (s.size() != out.size() * 2) {
        return std::unexpected("bad image name (want 64 hex digits)");
    }
    return out;
}

auto vtep(std::string_view s) -> std::expected<proto::VtepAddress, std::string> {
    const std::string text{s};
    proto::VtepAddress out{};
    in_addr v4{};
    if (inet_pton(AF_INET6, text.c_str(), out.data()) == 1) {
        return out;
    }
    if (inet_pton(AF_INET, text.c_str(), &v4) == 1) {  // as IPv4-mapped IPv6
        out[10] = std::byte{0xFF};
        out[11] = std::byte{0xFF};
        std::memcpy(out.data() + 12, &v4, sizeof(v4));
        return out;
    }
    return std::unexpected("bad VTEP address");
}

auto split(std::string_view s, char sep) -> std::vector<std::string_view> {
    std::vector<std::string_view> out;
    for (std::size_t start = 0;;) {
        const auto at = s.find(sep, start);
        out.push_back(s.substr(start, at == std::string_view::npos ? at : at - start));
        if (at == std::string_view::npos) {
            return out;
        }
        start = at + 1;
    }
}

// NIC,MAC,VTEP[,GUEST_IP ...]: one mapping entry and the guest addresses
// (IPv4 or IPv6) its NIC owns, appended to `m`.
auto add_map_entry(std::string_view s, SendMapUpdate& m) -> std::expected<void, std::string> {
    const auto fields = split(s, ',');
    if (fields.size() < 3) {
        return std::unexpected("map entry must be NIC,MAC,VTEP[,GUEST_IP ...]");
    }
    auto nic = number<std::uint64_t>(fields[0], "NIC id");
    auto addr = mac(fields[1]);
    auto v = vtep(fields[2]);
    if (!nic) {
        return std::unexpected(nic.error());
    }
    if (!addr) {
        return std::unexpected(addr.error());
    }
    if (!v) {
        return std::unexpected(v.error());
    }
    m.entries.push_back({.nic_id = *nic, .mac = *addr, .owner_vtep = *v});
    for (const auto ip : std::span{fields}.subspan(3)) {
        const std::string text{ip};
        proto::GuestIpv4 g4{.nic_id = *nic, .address = {}};
        proto::GuestIpv6 g6{.nic_id = *nic, .address = {}};
        if (inet_pton(AF_INET, text.c_str(), g4.address.data()) == 1) {
            m.ipv4.push_back(g4);
        } else if (inet_pton(AF_INET6, text.c_str(), g6.address.data()) == 1) {
            m.ipv6.push_back(g6);
        } else {
            return std::unexpected("bad guest address " + text);
        }
    }
    return {};
}

constexpr std::array status_names{
    std::pair{"ok", proto::CommandStatus::ok},
    std::pair{"accepted", proto::CommandStatus::accepted},
    std::pair{"bad_signature", proto::CommandStatus::bad_signature},
    std::pair{"stale_sequence", proto::CommandStatus::stale_sequence},
    std::pair{"malformed", proto::CommandStatus::malformed},
    std::pair{"unknown_vm", proto::CommandStatus::unknown_vm},
    std::pair{"unknown_device", proto::CommandStatus::unknown_device},
    std::pair{"unknown_volume", proto::CommandStatus::unknown_volume},
    std::pair{"insufficient_resources", proto::CommandStatus::insufficient_resources},
    std::pair{"conflict", proto::CommandStatus::conflict},
    std::pair{"timed_out", proto::CommandStatus::timed_out},
    std::pair{"internal_error", proto::CommandStatus::internal_error},
    std::pair{"unsupported", proto::CommandStatus::unsupported},
    std::pair{"wrong_server", proto::CommandStatus::wrong_server},
};

constexpr std::array kind_names{
    std::pair{"inventory", proto::ReportKind::inventory},
    std::pair{"command_outcome", proto::ReportKind::command_outcome},
    std::pair{"pool_state", proto::ReportKind::pool_state},
    std::pair{"vm_exited", proto::ReportKind::vm_exited},
    std::pair{"map_applied", proto::ReportKind::map_applied},
    std::pair{"host_fault", proto::ReportKind::host_fault},
    std::pair{"group_usage", proto::ReportKind::group_usage},
};

template<typename T, std::size_t N>
auto name_of(const std::array<std::pair<const char*, T>, N>& names, T value) -> const char* {
    for (const auto& [name, v] : names) {
        if (v == value) {
            return name;
        }
    }
    return "?";
}

template<typename T, std::size_t N>
auto value_of(const std::array<std::pair<const char*, T>, N>& names, std::string_view s)
    -> std::optional<T> {
    for (const auto& [name, v] : names) {
        if (s == name) {
            return v;
        }
    }
    return std::nullopt;
}

// Positional arguments, parsed in order; the first failure is kept and
// later reads return zero, so each command reads its fields straight
// through and checks once at the end.
class Args {
public:
    explicit Args(std::span<const std::string_view> args) : _args{args} {}

    template<std::unsigned_integral T> auto num(const char* what) -> T {
        return take(number<T>(next(), what));
    }
    auto device() -> mb::DeviceType { return take(device_type(next())); }
    auto mac_address() -> mb::Mac { return take(mac(next())); }
    auto image() -> mb::ImageName { return take(image_name(next())); }
    [[nodiscard]] auto more() const noexcept -> bool { return _pos < _args.size(); }
    auto detach_policy() -> mb::DetachPolicy { return take(policy(next())); }

    [[nodiscard]] auto error() const -> const std::string& { return _error; }

private:
    auto next() -> std::string_view { return _pos < _args.size() ? _args[_pos++] : ""; }

    template<typename T> auto take(std::expected<T, std::string> v) -> T {
        if (!v) {
            if (_error.empty()) {
                _error = v.error();
            }
            return T{};
        }
        return *v;
    }

    std::span<const std::string_view> _args;
    std::size_t _pos{0};
    std::string _error;
};

struct Verb {
    std::string_view name;
    std::size_t args;
    auto (*parse)(Args&) -> mb::Body;
    std::size_t optional_args{0};  // trailing arguments that may be left out
};

auto device_ref(Args& p, mb::DeviceType type) -> mb::DeviceRef {
    const auto slot = p.num<std::uint8_t>("slot");
    const auto fn = p.num<std::uint16_t>("function");
    return {.slot = slot, .type = type, .function = fn};
}

constexpr std::array verbs{
    Verb{"list-vms", 0, [](Args&) -> mb::Body { return mb::ListVms{}; }},
    Verb{"vm-status", 1,
         [](Args& p) -> mb::Body { return mb::VmStatus{.vm_id = p.num<std::uint64_t>("VM id")}; }},
    Verb{"create-vm", 3,
         [](Args& p) -> mb::Body {
             const auto vm = p.num<std::uint64_t>("VM id");
             const auto vcpus = p.num<std::uint16_t>("vcpu count");
             const auto mem = p.num<std::uint32_t>("memory size");
             return mb::CreateVm{
                 .vm_id = vm, .vcpus = vcpus, .memory_mib = mem, .boot_mode = mb::BootMode::volume};
         }},
    Verb{"destroy-vm", 1,
         [](Args& p) -> mb::Body {
             const auto vm = p.num<std::uint64_t>("VM id");
             // The optional "persist" is checked in command().
             return mb::DestroyVm{.vm_id = vm, .persist_volumes = p.more()};
         },
         1},
    // A NIC names its VPC, NIC ID and MAC (mailbox v3); a GPU names none.
    Verb{"attach-device", 4,
         [](Args& p) -> mb::Body {
             const auto vm = p.num<std::uint64_t>("VM id");
             const auto slot = p.num<std::uint8_t>("slot");
             const auto type = p.device();
             const auto fn = p.num<std::uint16_t>("function");
             mb::AttachDevice out{.vm_id = vm,
                                  .device = {.slot = slot, .type = type, .function = fn}};
             if (p.more()) {
                 out.vni = p.num<std::uint32_t>("VNI");
                 out.nic_id = p.num<std::uint64_t>("NIC id");
                 out.mac = p.mac_address();
             }
             return out;
         },
         3},
    Verb{"detach-device", 6,
         [](Args& p) -> mb::Body {
             const auto vm = p.num<std::uint64_t>("VM id");
             const auto slot = p.num<std::uint8_t>("slot");
             const auto type = p.device();
             const auto fn = p.num<std::uint16_t>("function");
             const auto timeout = p.num<std::uint16_t>("timeout");
             const auto pol = p.detach_policy();
             return mb::DetachDevice{.vm_id = vm,
                                     .device = {.slot = slot, .type = type, .function = fn},
                                     .timeout_s = timeout,
                                     .policy = pol};
         }},
    Verb{"create-volume", 3,
         [](Args& p) -> mb::Body {
             const auto vol = p.num<std::uint64_t>("volume id");
             const auto owner = p.num<std::uint64_t>("owner VM id");
             const auto size = p.num<std::uint32_t>("size");
             mb::CreateVolume out{.volume_id = vol, .owner_vm = owner, .size_gib = size};
             if (p.more()) {
                 out.image_store = p.num<std::uint16_t>("image store");
                 out.image_name = p.image();
             }
             return out;
         },
         2},
    Verb{"delete-volume", 1,
         [](Args& p) -> mb::Body {
             return mb::DeleteVolume{.volume_id = p.num<std::uint64_t>("volume id")};
         }},
    Verb{"attach-volume", 4,
         [](Args& p) -> mb::Body {
             const auto vol = p.num<std::uint64_t>("volume id");
             const auto vm = p.num<std::uint64_t>("VM id");
             const auto dev = device_ref(p, mb::DeviceType::blk_fn);
             return mb::AttachVolume{.volume_id = vol, .vm_id = vm, .device = dev};
         }},
    Verb{"detach-volume", 6,
         [](Args& p) -> mb::Body {
             const auto vol = p.num<std::uint64_t>("volume id");
             const auto vm = p.num<std::uint64_t>("VM id");
             const auto dev = device_ref(p, mb::DeviceType::blk_fn);
             const auto timeout = p.num<std::uint16_t>("timeout");
             const auto pol = p.detach_policy();
             return mb::DetachVolume{
                 .volume_id = vol, .vm_id = vm, .device = dev, .timeout_s = timeout, .policy = pol};
         }},
    Verb{"rewrap-volume", 3,
         [](Args& p) -> mb::Body {
             const auto vol = p.num<std::uint64_t>("volume id");
             const auto from = p.num<std::uint64_t>("from VM id");
             const auto to = p.num<std::uint64_t>("to VM id");
             return mb::RewrapVolume{.volume_id = vol, .from_vm = from, .to_vm = to};
         }},
    Verb{"create-network", 1,
         [](Args& p) -> mb::Body { return mb::CreateNetwork{.vni = p.num<std::uint32_t>("VNI")}; }},
    Verb{"delete-network", 1,
         [](Args& p) -> mb::Body { return mb::DeleteNetwork{.vni = p.num<std::uint32_t>("VNI")}; }},
};

// Parses arguments into a command body; `args` excludes the verb. Nothing
// (not an error) for a verb that is not a command.
auto command(std::string_view verb, std::span<const std::string_view> args)
    -> std::expected<std::optional<mb::Body>, std::string> {
    const auto* v = std::ranges::find(verbs, verb, &Verb::name);
    if (v == verbs.end()) {
        return std::optional<mb::Body>{};
    }
    if (args.size() != v->args && args.size() != v->args + v->optional_args) {
        return std::unexpected(std::string{verb} + ": wrong number of arguments");
    }
    if (verb == "destroy-vm" && args.size() == 2 && args[1] != "persist") {
        return std::unexpected("destroy-vm: second argument must be 'persist'");
    }
    Args p{args};
    auto body = v->parse(p);
    if (!p.error().empty()) {
        return std::unexpected(p.error());
    }
    return std::optional<mb::Body>{std::move(body)};
}

auto validate(const mb::Body& body) -> std::expected<void, std::string> {
    // Round-trip through the strict decoder hull uses, so a script typo
    // (VNI 0, a bad timeout) fails here with a message instead of as a
    // `malformed` outcome from hull.
    const auto bytes = mb::encode_body(body);
    mb::Message msg{};
    msg.header.type = mb::type_of(body);
    msg.header.body_len = static_cast<std::uint16_t>(bytes.size());
    msg.header.key_id = 1;
    msg.header.server_id = 1;
    if (bytes.size() > msg.body.size()) {
        return std::unexpected("command body too long");
    }
    std::ranges::copy(bytes, msg.body.begin());
    auto decoded = mb::decode_body(msg);
    if (!decoded) {
        return std::unexpected(std::string{"invalid command: "} + mb::to_string(decoded.error()));
    }
    return {};
}

}  // namespace

auto parse_line(std::string_view line) -> std::expected<std::optional<Action>, std::string> {
    const auto words = split(line);
    if (words.empty()) {
        return std::optional<Action>{};
    }
    const auto verb = words[0];
    const auto args = std::span{words}.subspan(1);
    if (verb == "expect") {
        if (args.size() != 1) {
            return std::unexpected("expect: want one status");
        }
        auto s = value_of(status_names, args[0]);
        if (!s) {
            return std::unexpected("expect: unknown status " + std::string{args[0]});
        }
        return std::optional<Action>{ExpectOutcome{.status = *s}};
    }
    if (verb == "wait") {
        if (args.size() != 1) {
            return std::unexpected("wait: want one report kind");
        }
        auto k = value_of(kind_names, args[0]);
        if (!k) {
            return std::unexpected("wait: unknown report kind " + std::string{args[0]});
        }
        return std::optional<Action>{WaitReport{.kind = *k}};
    }
    if (verb == "map-update") {
        if (args.size() < 2) {
            return std::unexpected(
                "map-update: want VNI VERSION [NIC,MAC,VTEP[,GUEST_IP ...] ...]");
        }
        auto vni = number<std::uint32_t>(args[0], "VNI");
        auto version = number<std::uint64_t>(args[1], "mapping version");
        if (!vni) {
            return std::unexpected(vni.error());
        }
        if (!version) {
            return std::unexpected(version.error());
        }
        SendMapUpdate m{
            .vni = *vni, .map_version = *version, .entries = {}, .ipv4 = {}, .ipv6 = {}};
        for (const auto e : args.subspan(2)) {
            if (auto ok = add_map_entry(e, m); !ok) {
                return std::unexpected(ok.error());
            }
        }
        // The frame's canonical order; duplicates are left for the encoder
        // to refuse.
        std::ranges::sort(m.entries, {}, &proto::MapEntry::nic_id);
        std::ranges::sort(m.ipv4, std::ranges::lexicographical_compare, &proto::GuestIpv4::address);
        std::ranges::sort(m.ipv6, std::ranges::lexicographical_compare, &proto::GuestIpv6::address);
        return std::optional<Action>{std::move(m)};
    }
    if (verb == "group-policy") {
        constexpr std::size_t multicast_args = 8;
        if (args.size() < 3) {
            return std::unexpected("group-policy: want VNI VERSION drop|multicast ...");
        }
        auto vni = number<std::uint32_t>(args[0], "VNI");
        auto version = number<std::uint64_t>(args[1], "policy version");
        if (!vni) {
            return std::unexpected(vni.error());
        }
        if (!version) {
            return std::unexpected(version.error());
        }
        SendGroupPolicy g{.vni = *vni, .policy_version = *version};
        if (args[2] == "drop" && args.size() == 3) {
            return std::optional<Action>{g};
        }
        if (args[2] != "multicast" ||
            (args.size() != multicast_args && args.size() != multicast_args + 1)) {
            return std::unexpected(
                "group-policy: want VNI VERSION drop, or VNI VERSION multicast RATE_FRAMES "
                "BURST_FRAMES RATE_BYTES BURST_BYTES MAX_REMOTE_VTEPS [MAX_GROUPS_PER_NIC]");
        }
        g.mode = proto::GroupMode::multicast;
        auto rate_frames = number<std::uint32_t>(args[3], "frame rate");
        auto burst_frames = number<std::uint32_t>(args[4], "frame burst");
        auto rate_bytes = number<std::uint64_t>(args[5], "byte rate");
        auto burst_bytes = number<std::uint64_t>(args[6], "byte burst");
        auto vteps = number<std::uint32_t>(args[7], "flood-list cap");
        for (const auto* r : {&rate_frames, &burst_frames, &vteps}) {
            if (!*r) {
                return std::unexpected(r->error());
            }
        }
        for (const auto* r : {&rate_bytes, &burst_bytes}) {
            if (!*r) {
                return std::unexpected(r->error());
            }
        }
        g.rate_frames = *rate_frames;
        g.burst_frames = *burst_frames;
        g.rate_bytes = *rate_bytes;
        g.burst_bytes = *burst_bytes;
        g.max_remote_vteps = *vteps;
        if (args.size() == multicast_args + 1) {
            auto groups = number<std::uint16_t>(args[multicast_args], "group cap");
            if (!groups) {
                return std::unexpected(groups.error());
            }
            g.max_groups_per_nic = *groups;
        }
        return std::optional<Action>{g};
    }
    auto body = command(verb, args);
    if (!body) {
        return std::unexpected(body.error());
    }
    if (!body->has_value()) {
        return std::unexpected("unknown action " + std::string{verb});
    }
    if (auto ok = validate(**body); !ok) {
        return std::unexpected(std::string{verb} + ": " + ok.error());
    }
    return std::optional<Action>{SendCommand{.body = std::move(**body)}};
}

auto to_string(const proto::Report& report) -> std::string {
    std::ostringstream os;
    os << "report seq=" << report.report_seq
       << " kind=" << name_of(kind_names, proto::report_kind(report.body));
    std::visit(
        [&os]<typename T>(const T& b) {
            if constexpr (std::is_same_v<T, proto::Inventory>) {
                os << " boot=0x" << std::hex << b.boot_id << std::dec
                   << " last_command_seq=" << b.last_command_seq << " cores=" << b.cores_free << "/"
                   << b.cores_total << " pages_1g=" << b.pages_1g_free << "/" << b.pages_1g_total
                   << " functions=" << b.functions.size() << " vms=" << b.vms.size()
                   << " volumes=" << b.volumes.size() << " networks=" << b.networks.size();
            } else if constexpr (std::is_same_v<T, proto::CommandOutcome>) {
                os << " in_reply_to=" << b.in_reply_to << " command=0x" << std::hex << b.command
                   << std::dec << " status=" << name_of(status_names, b.status)
                   << " payload=" << b.payload.size();
            } else if constexpr (std::is_same_v<T, proto::PoolStateChange>) {
                os << " slot=" << int{b.slot} << " fn=" << b.function
                   << " from=" << static_cast<int>(b.from) << " to=" << static_cast<int>(b.to)
                   << " vm=" << b.owner_vm;
            } else if constexpr (std::is_same_v<T, proto::VmExitedReport>) {
                os << " vm=" << b.vm_id << " exit_status=" << b.exit_status
                   << " reason=" << static_cast<int>(b.reason);
            } else if constexpr (std::is_same_v<T, proto::MapApplied>) {
                os << " vni=" << b.vni << " version=" << b.map_version;
            } else if constexpr (std::is_same_v<T, proto::GroupUsage>) {
                os << " entries=" << b.entries.size();
                for (const auto& e : b.entries) {
                    os << " [slot=" << int{e.slot} << " nic=0x" << std::hex << e.nic_id << std::dec
                       << " attachment=" << e.attachment << (e.detached ? " detached" : "")
                       << " frames=" << e.frames << " replicas_remote=" << e.replicas_remote
                       << " replica_bytes_remote=" << e.replica_bytes_remote << "]";
                }
            } else {
                os << " code=" << static_cast<int>(b.code) << " slot=" << int{b.slot}
                   << " detail=0x" << std::hex << b.detail << std::dec;
            }
        },
        report.body);
    return os.str();
}

// ---- TestController -------------------------------------------------------

TestController::TestController(ControllerOptions options, Signer signer, tls::Context ctx)
    : _options{std::move(options)}, _signer{std::move(signer)}, _ctx{std::move(ctx)} {}

auto TestController::create(ControllerOptions options, Signer signer)
    -> std::expected<TestController, std::string> {
    if (options.server_id == 0) {
        return std::unexpected("server id must be non-zero");
    }
    if (options.key_id == proto::no_key_id) {
        return std::unexpected("key id must be non-zero");
    }
    options.tls.role = tls::Role::server;
    auto ctx = tls::Context::create(options.tls);
    if (!ctx) {
        return std::unexpected(std::string{"TLS configuration: "} + tls::to_string(ctx.error()));
    }
    return TestController{std::move(options), std::move(signer), std::move(*ctx)};
}

auto TestController::send(proto::RecordType type, std::span<const std::byte> payload)
    -> std::expected<void, std::string> {
    if (!_stream) {
        return std::unexpected("not connected");
    }
    auto rec = proto::encode_record(type, payload);
    if (!rec) {
        return std::unexpected(std::string{"framing: "} + proto::to_string(rec.error()));
    }
    if (auto ok = _stream->write_all(*rec, tls::Clock::now() + _options.timeout); !ok) {
        return std::unexpected(std::string{"send: "} + tls::to_string(ok.error()));
    }
    return {};
}

auto TestController::handle(const proto::Record& rec)
    -> std::expected<std::optional<proto::Report>, std::string> {
    switch (rec.type) {
        case proto::RecordType::hello: {
            auto hello = proto::decode_hello(rec.payload);
            if (!hello) {
                return std::unexpected(std::string{"hello: "} + proto::to_string(hello.error()));
            }
            if (hello->server_id != _options.server_id) {
                return std::unexpected("hello from server " + std::to_string(hello->server_id) +
                                       ", expected " + std::to_string(_options.server_id));
            }
            if (hello->boot_id != _boot_id) {
                _boot_id = hello->boot_id;  // a new boot: its sequence restarts
                _last_report_seq = 0;
            }
            return std::optional<proto::Report>{};
        }
        case proto::RecordType::report: {
            if (_boot_id == 0) {
                return std::unexpected("report before hello");
            }
            auto report = proto::decode_report(rec.payload);
            if (!report) {
                return std::unexpected(std::string{"report: "} + proto::to_string(report.error()));
            }
            if (report->server_id != _options.server_id) {
                return std::unexpected("report from another server");
            }
            auto ack = proto::encode_report_ack(
                {.server_id = _options.server_id, .report_seq = report->report_seq});
            if (auto ok = send(proto::RecordType::report_ack, *ack); !ok) {
                return std::unexpected(ok.error());
            }
            if (report->report_seq <= _last_report_seq) {
                return std::optional<proto::Report>{};  // a replay we already have
            }
            _last_report_seq = report->report_seq;
            if (const auto* inv = std::get_if<proto::Inventory>(&report->body)) {
                _inventory = *inv;
                // Commands resume after the last one hull accepted.
                _next_seq = std::max(_next_seq, inv->last_command_seq + 1);
            }
            if (_options.on_report) {
                _options.on_report(*report);
            }
            return std::optional<proto::Report>{std::move(*report)};
        }
        case proto::RecordType::envelope:
        case proto::RecordType::map_update:
        case proto::RecordType::group_policy:
        case proto::RecordType::report_ack:
            break;
    }
    return std::unexpected("helm sent a controller-only record");
}

auto TestController::pump(const std::function<bool(const proto::Report&)>& done)
    -> std::expected<proto::Report, std::string> {
    if (auto it = std::ranges::find_if(_backlog, done); it != _backlog.end()) {
        auto r = std::move(*it);
        _backlog.erase(it);
        return r;
    }
    if (!_stream) {
        return std::unexpected("not connected");
    }
    const auto deadline = tls::Clock::now() + _options.timeout;
    std::array<std::byte, 16 * 1024> buf{};
    while (tls::Clock::now() < deadline) {
        for (;;) {
            auto rec = _decoder.next();
            if (!rec) {
                return std::unexpected(std::string{"stream: "} + proto::to_string(rec.error()));
            }
            if (!rec->has_value()) {
                break;
            }
            auto report = handle(**rec);
            if (!report) {
                return std::unexpected(report.error());
            }
            if (report->has_value()) {
                if (done(**report)) {
                    return std::move(**report);
                }
                _backlog.push_back(std::move(**report));
            }
        }
        if (!_stream->pending()) {
            const auto left =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - tls::Clock::now());
            pollfd p{.fd = _stream->fd(), .events = POLLIN, .revents = 0};
            (void)poll(&p, 1, static_cast<int>(std::clamp<std::int64_t>(left.count(), 0, 1000)));
        }
        auto got = _stream->read_some(buf);
        if (!got) {
            return std::unexpected(std::string{"connection: "} + tls::to_string(got.error()));
        }
        _decoder.feed(std::span{buf}.first(*got));
    }
    return std::unexpected("timed out");
}

auto TestController::accept(tls::Listener& listener) -> std::expected<void, std::string> {
    const auto deadline = tls::Clock::now() + _options.timeout;
    auto fd = listener.accept_fd(deadline);
    if (!fd) {
        return std::unexpected(std::string{"accept: "} + tls::to_string(fd.error()));
    }
    auto stream = tls::Stream::accept(_ctx, *fd, deadline);
    if (!stream) {
        return std::unexpected(std::string{"handshake: "} + tls::to_string(stream.error()));
    }
    _stream = std::move(*stream);
    _decoder = proto::RecordDecoder{};
    _backlog.clear();
    auto inv = pump(
        [](const proto::Report& r) { return std::holds_alternative<proto::Inventory>(r.body); });
    if (!inv) {
        return std::unexpected("registration: " + inv.error());
    }
    return {};
}

auto TestController::run(const Action& action) -> std::expected<void, std::string> {
    return std::visit(
        [this]<typename T>(const T& a) -> std::expected<void, std::string> {
            if constexpr (std::is_same_v<T, SendCommand>) {
                const auto seq = _next_seq;
                auto env = _signer.envelope(_options.server_id, _options.key_id, seq, a.body);
                if (!env) {
                    return std::unexpected("could not sign the command");
                }
                if (auto ok = send(proto::RecordType::envelope, *env); !ok) {
                    return ok;
                }
                _last_command_seq = seq;
                ++_next_seq;
                return {};
            } else if constexpr (std::is_same_v<T, SendMapUpdate>) {
                const proto::MapUpdate m{.server_id = _options.server_id,
                                         .key_id = _options.key_id,
                                         .vni = a.vni,
                                         .map_version = a.map_version,
                                         .entries = a.entries,
                                         .ipv4 = a.ipv4,
                                         .ipv6 = a.ipv6,
                                         .signature = {}};
                auto frame = _signer.map_update(m);
                if (!frame) {
                    return std::unexpected("could not encode or sign the mapping update");
                }
                return send(proto::RecordType::map_update, *frame);
            } else if constexpr (std::is_same_v<T, SendGroupPolicy>) {
                const proto::GroupPolicy g{.server_id = _options.server_id,
                                           .key_id = _options.key_id,
                                           .vni = a.vni,
                                           .mode = a.mode,
                                           .policy_version = a.policy_version,
                                           .rate_frames = a.rate_frames,
                                           .burst_frames = a.burst_frames,
                                           .rate_bytes = a.rate_bytes,
                                           .burst_bytes = a.burst_bytes,
                                           .max_remote_vteps = a.max_remote_vteps,
                                           .max_groups_per_nic = a.max_groups_per_nic,
                                           .signature = {}};
                auto frame = _signer.group_policy(g);
                if (!frame) {
                    return std::unexpected("could not encode or sign the group policy");
                }
                return send(proto::RecordType::group_policy, *frame);
            } else if constexpr (std::is_same_v<T, ExpectOutcome>) {
                if (_last_command_seq == 0) {
                    return std::unexpected("expect: no command sent yet");
                }
                const auto want_seq = _last_command_seq;
                auto r = pump([want_seq](const proto::Report& rep) {
                    const auto* o = std::get_if<proto::CommandOutcome>(&rep.body);
                    return o != nullptr && o->in_reply_to == want_seq;
                });
                if (!r) {
                    return std::unexpected("expect: " + r.error());
                }
                const auto got = std::get<proto::CommandOutcome>(r->body).status;
                if (got != a.status) {
                    return std::unexpected(
                        std::string{"expect: command "} + std::to_string(want_seq) + " got " +
                        name_of(status_names, got) + ", wanted " + name_of(status_names, a.status));
                }
                return {};
            } else {
                auto r = pump([&a](const proto::Report& rep) {
                    return proto::report_kind(rep.body) == a.kind;
                });
                if (!r) {
                    return std::unexpected("wait: " + r.error());
                }
                return {};
            }
        },
        action);
}

}  // namespace ak::harbor
