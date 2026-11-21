# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# ak_common: header-only wire helpers shared by every role.
add_library(ak_common INTERFACE)
add_library(ak::common ALIAS ak_common)
target_include_directories(ak_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# ak_proto: header-only controller wire formats (Envelope, MapUpdate,
# Report, link records) and the signing test vectors. Depends only on ak_common so kythira's EC2
# module can include it directly (.kiro/specs/controller-interface/).
add_library(ak_proto INTERFACE)
add_library(ak::proto ALIAS ak_proto)
target_link_libraries(ak_proto INTERFACE ak::common)

# oar-net: Geneve encapsulation, VTEP ingress policy and runtime, the
# WireGuard underlay, the controller mapping table, the VSwitch and the
# virtio-net function (network data plane).
add_library(ak_oar_net
  oar/net/geneve.cpp
  oar/net/mapping_table.cpp
  oar/net/mtu.cpp
  oar/net/neighbor.cpp
  oar/net/oam.cpp
  oar/net/tunnel.cpp
  oar/net/udp_endpoint.cpp
  oar/net/virtio_net.cpp
  oar/net/vswitch.cpp
  oar/net/vtep.cpp
  oar/net/vtep_policy.cpp
  oar/net/wireguard.cpp)
add_library(ak::oar_net ALIAS ak_oar_net)
target_link_libraries(ak_oar_net
  PUBLIC ak::common ak::oar_virtio
  PRIVATE ak::warnings ak::hardening)

# oar/virtio: the shared virtio device core (guest memory, split virtqueue,
# modern PCI capabilities and common configuration), written once and bound
# to vfio-user or pci-epf by each device.
add_library(ak_oar_virtio
  oar/virtio/function.cpp
  oar/virtio/guest_memory.cpp
  oar/virtio/pci.cpp
  oar/virtio/split_queue.cpp)
add_library(ak::oar_virtio ALIAS ak_oar_virtio)
target_link_libraries(ak_oar_virtio
  PUBLIC ak::common
  PRIVATE ak::warnings ak::hardening)

# OpenSSL is required: AES-256-GCM key wrapping and OPENSSL_cleanse in the
# helm key store, and Ed25519 in hull (the only implementation here). CI
# builds against Ubuntu 24.04's OpenSSL 3.0, so 3.0 is the configure floor.
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)
# oar-net's WireGuard underlay: X25519, ChaCha20-Poly1305, BLAKE2s.
target_link_libraries(ak_oar_net PRIVATE OpenSSL::Crypto)

# ak_tls: mutually authenticated TLS 1.3 over TCP for the ControllerLink
# (helm the client, the controller or harbor's test controller the server).
add_library(ak_tls tls/tls.cpp)
add_library(ak::tls ALIAS ak_tls)
target_include_directories(ak_tls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ak_tls
  PRIVATE OpenSSL::SSL OpenSSL::Crypto ak::warnings ak::hardening)

# helm: control-plane mailbox protocol and register file, device pool, MCTP sideband framing,
# OarLink (sideband protocol and its transport bindings), key store, the
# ControllerLink, the CommandRouter, the audit log, the PowerSequencer
# (with harbor's process backplane) and the daemon that wires them
# (HelmDaemon, ak-helm's configuration).
add_library(ak_helm
  helm/audit_log.cpp
  helm/command_router.cpp
  helm/group_usage.cpp
  helm/controller_link.cpp
  helm/device_pool.cpp
  helm/helm_config.cpp
  helm/helm_daemon.cpp
  helm/key_store.cpp
  helm/mailbox.cpp
  helm/mailbox_device.cpp
  helm/mctp.cpp
  helm/oar_link.cpp
  helm/oar_protocol.cpp
  helm/power_sequencer.cpp
  helm/scoped_key.cpp
  helm/secure_element.cpp
  helm/sideband_binding.cpp)
add_library(ak::helm ALIAS ak_helm)
target_link_libraries(ak_helm
  PUBLIC ak::common ak::proto ak::tls
  PRIVATE OpenSSL::Crypto ak::warnings ak::hardening)

# ak-helm: the helm daemon as harbor runs it (board processes, socket
# sidebands, the ControllerLink).
add_executable(ak-helm helm/helm_main.cpp)
target_link_libraries(ak-helm PRIVATE ak::helm ak::warnings ak::hardening)
install(TARGETS ak-helm RUNTIME DESTINATION bin)

# hull: host-agent command authentication (Ed25519 signatures and sequence
# numbers), the mailbox client and its VFIO mapping, the core / huge-page
# allocator, and the per-VMM jail and cgroup.
add_library(ak_hull
  hull/command_auth.cpp
  hull/cpu_topology.cpp
  hull/jail.cpp
  hull/mailbox_client.cpp
  hull/resource_allocator.cpp
  hull/sequence_tracker.cpp
  hull/signature_verifier.cpp
  hull/vfio_mailbox.cpp
  hull/vm_cgroup.cpp)
add_library(ak::hull ALIAS ak_hull)
target_link_libraries(ak_hull
  PUBLIC ak::common ak::helm OpenSSL::Crypto
  PRIVATE ak::warnings ak::hardening)

# The controller's volume state machine (.kiro/specs/block-volume-service/
# task 4): placement, epochs, leases, failover, rebuild, moves, snapshots
# and GC over an abstract transport. The simulation and harbor drive it;
# kythira's EC2 module ports it.
add_library(ak_hold_master hold/master/master.cpp)
add_library(ak::hold_master ALIAS ak_hold_master)
target_link_libraries(ak_hold_master
  PUBLIC ak::proto
  PRIVATE ak::warnings ak::hardening)

# harbor's test controller: signs commands and mapping updates and drives
# one helm over the ControllerLink, standing in for kythira's EC2 module
# until it exists (.kiro/specs/controller-interface/ task 5).
add_library(ak_harbor_controller harbor/test_controller.cpp)
add_library(ak::harbor_controller ALIAS ak_harbor_controller)
target_link_libraries(ak_harbor_controller
  PUBLIC ak::helm ak::proto ak::tls
  PRIVATE OpenSSL::Crypto ak::warnings ak::hardening)
add_executable(ak-test-controller harbor/ak_test_controller.cpp)
target_link_libraries(ak-test-controller
  PRIVATE ak::harbor_controller ak::warnings ak::hardening)
install(TARGETS ak-test-controller RUNTIME DESTINATION bin)

# harbor phase 2's guest program: drives an ak-testdev function through
# vfio from inside the L2 guest. Linked statically (as a static PIE, so the
# hardening flags still apply) because the L2 guest is a bare initramfs
# with no shared libraries.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(ak-guest-testdev harbor/guest_testdev.cpp)
  target_link_libraries(ak-guest-testdev PRIVATE ak::warnings ak::hardening)
  # -static-pie goes in the link libraries, not target_link_options, so it
  # comes after ak::hardening's -pie on the command line and wins. The
  # sanitizer runtimes cannot be linked statically, so sanitizer builds
  # (CI only compiles it there) stay dynamic.
  if(NOT AK_SANITIZE)
    target_link_libraries(ak-guest-testdev PRIVATE -static-pie)
  endif()
  install(TARGETS ak-guest-testdev RUNTIME DESTINATION bin)
endif()

# oar-blk: AES-256-XTS volume encryption, the locked key slot, the
# virtio-blk request parser and the virtio-blk function on the shared
# virtio core (storage data plane).
add_library(ak_oar_blk
  oar/blk/file_backend.cpp
  oar/blk/key_slot.cpp
  oar/blk/request_parser.cpp
  oar/blk/virtio_blk_function.cpp
  oar/blk/xts_cipher.cpp)
add_library(ak::oar_blk ALIAS ak_oar_blk)
target_link_libraries(ak_oar_blk
  PUBLIC ak::common ak::oar_virtio OpenSSL::Crypto
  PRIVATE ak::warnings ak::hardening)

# The network role as helm drives it over the sideband: the VTEP's
# MappingTable, VSwitch and Vtep, and one virtio-net function per
# transport (oar-net tasks 9 and 11). Apart from ak_oar_net for the same
# reason as ak_oar_blk_role.
add_library(ak_oar_net_role oar/net/net_role.cpp)
add_library(ak::oar_net_role ALIAS ak_oar_net_role)
target_link_libraries(ak_oar_net_role
  PUBLIC ak::oar_net ak::helm ak::proto
  PRIVATE ak::warnings ak::hardening)

# oar-blk image volumes: a read-only base image in object storage under an
# ephemeral overlay (.kiro/specs/oar-blk-data-plane/ Requirement 8).
add_library(ak_oar_blk_image
  oar/blk/chunk_cache.cpp
  oar/blk/fetcher.cpp
  oar/blk/image_manifest.cpp
  oar/blk/image_pack.cpp
  oar/blk/lazy_image_backend.cpp
  oar/blk/object_store.cpp
  oar/blk/overlay.cpp)
add_library(ak::oar_blk_image ALIAS ak_oar_blk_image)
find_package(Threads REQUIRED)
target_link_libraries(ak_oar_blk_image
  PUBLIC ak::oar_blk Threads::Threads
  PRIVATE ak::warnings ak::hardening)

# Packs a raw disk image into an image volume's manifest and data objects
# (oar-blk task 12).
add_executable(ak-image-pack oar/blk/image_pack_main.cpp)
target_link_libraries(ak-image-pack
  PRIVATE ak::oar_blk_image OpenSSL::Crypto ak::warnings ak::hardening)
install(TARGETS ak-image-pack RUNTIME DESTINATION bin)

# The S3 client behind image volumes: HTTP/1.1 range GETs over TCP or TLS
# with Signature V4 (oar-blk task 11).
add_library(ak_oar_blk_s3
  oar/blk/http_response.cpp
  oar/blk/s3_object_store.cpp
  oar/blk/sigv4.cpp)
add_library(ak::oar_blk_s3 ALIAS ak_oar_blk_s3)
target_link_libraries(ak_oar_blk_s3
  PUBLIC ak::oar_blk_image OpenSSL::SSL OpenSSL::Crypto
  PRIVATE ak::warnings ak::hardening)

# The storage role as helm drives it over the sideband: volume files and
# one virtio-blk function per transport (oar-blk task 6). Kept apart from
# ak_oar_blk so the data path does not depend on helm's library.
add_library(ak_oar_blk_role oar/blk/blk_role.cpp)
add_library(ak::oar_blk_role ALIAS ak_oar_blk_role)
target_link_libraries(ak_oar_blk_role
  PUBLIC ak::oar_blk ak::helm
  PRIVATE ak::warnings ak::hardening)

# vfio-user device servers, built against libvfio-user (the `vfio-user`
# vcpkg feature, vcpkg-overlays/libvfio-user).
#
# AK_VFIO_USER picks what happens when libvfio-user is missing:
#   AUTO  build the device servers if libvfio-user is found, otherwise skip
#         them (kythira's graceful-degradation pattern). If the vcpkg feature
#         is installed, AUTO behaves like ON: a feature that is installed but
#         cannot be found is a bug, not an absent optional dependency.
#   ON    a missing libvfio-user is a configure error.
#   OFF   never build them.
set(AK_VFIO_USER AUTO CACHE STRING "Build vfio-user device servers: AUTO, ON or OFF")
set_property(CACHE AK_VFIO_USER PROPERTY STRINGS AUTO ON OFF)
if(NOT AK_VFIO_USER MATCHES "^(AUTO|ON|OFF)$")
  message(FATAL_ERROR "AK_VFIO_USER must be AUTO, ON or OFF (got '${AK_VFIO_USER}')")
endif()

set(_ak_vfio_user_required OFF)
set(_ak_vfio_user_reason "")
if(AK_VFIO_USER STREQUAL "ON")
  set(_ak_vfio_user_required ON)
  set(_ak_vfio_user_reason "AK_VFIO_USER=ON")
elseif(AK_VFIO_USER STREQUAL "AUTO")
  # vcpkg installs the port's copyright file here; its presence means the
  # `vfio-user` feature was installed into this tree.
  set(_ak_vfio_user_port "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/share/libvfio-user")
  if(EXISTS "${_ak_vfio_user_port}")
    set(_ak_vfio_user_required ON)
    set(_ak_vfio_user_reason "the vcpkg `vfio-user` feature is installed (${_ak_vfio_user_port})")
  endif()
  unset(_ak_vfio_user_port)
endif()

if(NOT AK_VFIO_USER STREQUAL "OFF")
  # Preferred: libvfio-user.pc. Upstream installs none, so the overlay port
  # generates one; a hand-written one on PKG_CONFIG_PATH works too.
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBVFIO_USER QUIET IMPORTED_TARGET libvfio-user)
  endif()
  if(LIBVFIO_USER_FOUND)
    add_library(ak_libvfio_user INTERFACE)
    target_link_libraries(ak_libvfio_user INTERFACE PkgConfig::LIBVFIO_USER)
    set(_ak_vfio_user_via "pkg-config, version ${LIBVFIO_USER_VERSION}")
  else()
    # Fallback for a plain upstream `meson install` (no .pc file): find the
    # header and library directly. json-c is needed too, since the library
    # may be static.
    find_path(LIBVFIO_USER_INCLUDE_DIR libvfio-user.h PATH_SUFFIXES vfio-user)
    find_library(LIBVFIO_USER_LIBRARY vfio-user)
    find_package(json-c CONFIG QUIET)
    if(LIBVFIO_USER_INCLUDE_DIR AND LIBVFIO_USER_LIBRARY AND TARGET json-c::json-c)
      find_package(Threads REQUIRED)
      add_library(ak_libvfio_user INTERFACE)
      target_include_directories(ak_libvfio_user SYSTEM INTERFACE ${LIBVFIO_USER_INCLUDE_DIR})
      target_link_libraries(ak_libvfio_user INTERFACE
        ${LIBVFIO_USER_LIBRARY} json-c::json-c Threads::Threads)
      set(LIBVFIO_USER_FOUND ON)
      set(_ak_vfio_user_via "${LIBVFIO_USER_LIBRARY}")
    endif()
  endif()
endif()

if(LIBVFIO_USER_FOUND)
  set(AK_HAS_LIBVFIO_USER ON CACHE INTERNAL "libvfio-user found")
  message(STATUS "libvfio-user (${_ak_vfio_user_via}): building vfio-user device servers")
  add_executable(ak-testdev oar/testdev/main.cpp)
  target_link_libraries(ak-testdev PRIVATE ak_libvfio_user ak::common ak::warnings ak::hardening)
  # libvfio-user's capability headers are C with bit-fields and packed
  # structs; keep our strict flags but do not fail on its headers.
  target_compile_options(ak-testdev PRIVATE -Wno-pedantic)
  install(TARGETS ak-testdev RUNTIME DESTINATION bin)

  # The harbor transport for every virtio device: a PciFunction served over
  # vfio-user (oar/vfu/virtio_binding.hpp).
  add_library(ak_vfu_virtio oar/vfu/virtio_binding.cpp)
  add_library(ak::vfu_virtio ALIAS ak_vfu_virtio)
  target_link_libraries(ak_vfu_virtio
    PUBLIC ak::oar_virtio
    PRIVATE ak_libvfio_user ak::warnings ak::hardening)
  target_compile_options(ak_vfu_virtio PRIVATE -Wno-pedantic)

  # helm's mailbox function served over vfio-user (helm task 8).
  add_library(ak_helm_vfu helm/mailbox_vfu_server.cpp)
  add_library(ak::helm_vfu ALIAS ak_helm_vfu)
  target_link_libraries(ak_helm_vfu
    PUBLIC ak::helm
    PRIVATE ak_libvfio_user ak::warnings ak::hardening)
  target_compile_options(ak_helm_vfu PRIVATE -Wno-pedantic)

  add_executable(ak-oar-net oar/net/oar_net_main.cpp)
  target_link_libraries(ak-oar-net
    PRIVATE ak::vfu_virtio ak::oar_net_role ak::hull ak::warnings ak::hardening)
  install(TARGETS ak-oar-net RUNTIME DESTINATION bin)

  add_executable(ak-oar-blk oar/blk/oar_blk_main.cpp)
  target_link_libraries(ak-oar-blk
    PRIVATE ak::vfu_virtio ak::oar_blk_role ak::warnings ak::hardening)
  install(TARGETS ak-oar-blk RUNTIME DESTINATION bin)
elseif(_ak_vfio_user_required)
  message(FATAL_ERROR
    "libvfio-user not found, but it is required because ${_ak_vfio_user_reason}.\n"
    "Looked for libvfio-user.pc on PKG_CONFIG_PATH, then for libvfio-user.h and "
    "libvfio-user (with json-c) under CMAKE_PREFIX_PATH.\n"
    "If vcpkg built it, re-run `vcpkg install --x-feature=vfio-user` so the overlay "
    "port regenerates libvfio-user.pc. Pass -DAK_VFIO_USER=OFF to build without "
    "the vfio-user device servers.")
else()
  set(AK_HAS_LIBVFIO_USER OFF CACHE INTERNAL "libvfio-user found")
  if(AK_VFIO_USER STREQUAL "OFF")
    message(STATUS "AK_VFIO_USER=OFF: vfio-user device servers not built")
  else()
    message(WARNING "libvfio-user not found: vfio-user device servers (ak-testdev, ak-oar-net, ak-oar-blk) not built. "
                    "Install the `vfio-user` vcpkg feature to enable them, or pass "
                    "-DAK_VFIO_USER=OFF to silence this warning.")
  endif()
endif()
unset(_ak_vfio_user_required)
unset(_ak_vfio_user_reason)
unset(_ak_vfio_user_via)
