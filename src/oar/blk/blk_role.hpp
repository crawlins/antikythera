// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// BlkRole: the storage data-plane role as helm sees it over the sideband
// (.kiro/specs/oar-blk-data-plane/ Requirement 3, task 6): a fixed set of
// virtio-blk PCI functions and a directory of volume files (FileBackend),
// driven by helm's OarLink requests.
//
//   create_volume     a new volume file holding the wrapped key helm sent
//   prepare_function  open a volume for one VM and put it behind a function;
//                     the function holds the guest's I/O until the key comes
//                     (VirtioBlkFunction::await_key)
//   deliver_key       load the volume key into that function
//   drop_key          wipe it
//   clean_function    wipe the key and close the volume: the function is
//                     back to its empty placeholder
//   rewrap_volume     new owner and wrapped key in the volume's header
//   delete_volume     erase and unlink the volume file (closing it first if
//                     a function still has it: helm deletes the volumes of a
//                     destroyed VM before their functions are cleaned)
//
// Each function sits on a FunctionTransport (vfio-user in harbor). The
// transport exists for the life of the role, since the client (L0 QEMU in
// harbor) attaches at boot; what it serves changes with each attachment.
// Between attachments it serves a placeholder: a virtio-blk function over
// an empty backend with no key, so nothing a stray driver does reaches a
// volume. Every function, placeholder or not, has the same queues and so
// the same PCI shape, which is what lets a transport swap them.
//
// The volume files are named vol-<16 hex digits>.akv in the volume
// directory. The role checks a volume's header against the request: a
// prepare for a VM other than the volume's owner is refused, as helm's
// KeyStore would refuse to unwrap its key anyway.
//
// Not thread-safe: the sideband and the transports share one thread.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "helm/oar_link.hpp"
#include "oar/blk/virtio_blk_function.hpp"

namespace ak::oar::blk {

// One PCI function's transport, as the role drives it.
class FunctionTransport {
public:
    FunctionTransport() = default;
    FunctionTransport(const FunctionTransport&) = delete;
    auto operator=(const FunctionTransport&) -> FunctionTransport& = delete;
    FunctionTransport(FunctionTransport&&) = delete;
    auto operator=(FunctionTransport&&) -> FunctionTransport& = delete;
    virtual ~FunctionTransport() = default;

    // The guest memory and interrupts every function on this transport uses.
    [[nodiscard]] virtual auto memory() -> const virtio::GuestMemory& = 0;
    [[nodiscard]] virtual auto interrupts() -> virtio::InterruptSink& = 0;
    // Serves `function` from now on; `on_flr` runs on the transport's
    // function-level reset instead of PciFunction::reset (it must wipe the
    // key: VirtioBlkFunction::function_reset). `function` stays valid until
    // the next serve().
    [[nodiscard]] virtual auto serve(virtio::PciFunction& function, std::function<void()> on_flr)
        -> std::expected<void, std::string> = 0;
};

struct RoleConfig {
    using Clock = std::chrono::steady_clock;

    std::filesystem::path volume_dir;
    std::uint16_t num_queues{1};
    std::uint16_t queue_size{256};
    std::uint32_t seg_max{128};
    std::uint32_t max_transfer_bytes{1U << 20U};
    std::size_t budget{256};
    // Empty: steady_clock::now (health's uptime).
    std::function<Clock::time_point()> clock;
};

// What a GET_ID returns for a volume: "akv-" and its ID in 16 hex digits,
// exactly the 20 bytes virtio-blk allows.
[[nodiscard]] auto volume_serial(std::uint64_t volume_id) -> std::string;

class BlkRole final : public helm::OarHandler {
public:
    // One function per transport, numbered from 0 in order; each starts on
    // its placeholder. Every transport must outlive the role.
    [[nodiscard]] static auto create(RoleConfig config,
                                     const std::vector<FunctionTransport*>& transports)
        -> std::expected<std::unique_ptr<BlkRole>, std::string>;

    BlkRole(const BlkRole&) = delete;
    auto operator=(const BlkRole&) -> BlkRole& = delete;
    BlkRole(BlkRole&&) = delete;
    auto operator=(BlkRole&&) -> BlkRole& = delete;
    ~BlkRole() override;

    // helm::OarHandler
    auto function_inventory() -> std::expected<helm::oar::Inventory, helm::oar::Status> override;
    auto prepare_function(const helm::oar::PrepareFunction& request) -> helm::oar::Status override;
    auto clean_function(const helm::oar::CleanFunction& request) -> helm::oar::Status override;
    auto deliver_key(const helm::oar::DeliverKey& request) -> helm::oar::Status override;
    auto drop_key(const helm::oar::DropKey& request) -> helm::oar::Status override;
    auto map_update(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto health() -> std::expected<helm::oar::Health, helm::oar::Status> override;
    auto create_volume(const helm::oar::CreateVolume& request) -> helm::oar::Status override;
    auto delete_volume(const helm::oar::DeleteVolume& request) -> helm::oar::Status override;
    auto rewrap_volume(const helm::oar::RewrapVolume& request) -> helm::oar::Status override;

    // Serves deferred requests on every attached function; true if any
    // still has work (call again soon).
    auto poll() -> bool;
    // The backends' wake descriptors (VirtioBlkFunction::wake_fd) of the
    // attached functions, for the event loop to sleep on alongside the
    // transports; call poll() when one is readable.
    [[nodiscard]] auto wake_fds() const -> std::vector<int>;

    [[nodiscard]] auto volume_path(std::uint64_t volume_id) const -> std::filesystem::path;
    [[nodiscard]] auto function_count() const noexcept -> std::size_t { return _slots.size(); }
    // The volume function `fn` has open, if any.
    [[nodiscard]] auto attached(helm::oar::FunctionNumber fn) const -> std::optional<std::uint64_t>;
    // The attached function itself (tests, counters); null between attachments.
    [[nodiscard]] auto function(helm::oar::FunctionNumber fn) -> VirtioBlkFunction*;

private:
    struct Slot {
        FunctionTransport* transport{nullptr};
        std::unique_ptr<VirtioBlkFunction> placeholder;
        std::unique_ptr<VirtioBlkFunction> active;
        std::uint64_t volume{0};
    };

    explicit BlkRole(RoleConfig config) : _config{std::move(config)} {}

    [[nodiscard]] auto slot(helm::oar::FunctionNumber fn) -> Slot*;
    [[nodiscard]] auto slot_of_volume(std::uint64_t volume) -> Slot*;
    [[nodiscard]] auto params(const VolumeGeometry& geometry, std::string_view serial) const
        -> BlkParams;
    // Wipes the key, closes the volume and puts the placeholder back.
    auto close(Slot& s) -> bool;

    RoleConfig _config;
    std::vector<Slot> _slots;
    RoleConfig::Clock::time_point _started;
};

}  // namespace ak::oar::blk
