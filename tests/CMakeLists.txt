# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Boost.Test, as in kythira: one executable per test file, each defining its
# own BOOST_TEST_MODULE. vcpkg supplies a static Boost.Test; a system build
# may be shared, which needs BOOST_TEST_DYN_LINK.
find_package(Boost REQUIRED COMPONENTS unit_test_framework)
# The TLS tests build a throwaway PKI with OpenSSL (tls_test_support.hpp).
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

set(_ak_boost_test_dyn OFF)
get_target_property(_ak_bt_type Boost::unit_test_framework TYPE)
if(_ak_bt_type STREQUAL "SHARED_LIBRARY")
  set(_ak_boost_test_dyn ON)
else()
  foreach(_prop IMPORTED_LOCATION IMPORTED_LOCATION_RELEASE IMPORTED_LOCATION_NOCONFIG)
    get_target_property(_ak_bt_loc Boost::unit_test_framework ${_prop})
    if(_ak_bt_loc MATCHES "\\.so")
      set(_ak_boost_test_dyn ON)
    endif()
  endforeach()
endif()

function(ak_add_test name)
  cmake_parse_arguments(ARG "" "" "SOURCES;LIBS;ARGS" ${ARGN})
  add_executable(${name} ${ARG_SOURCES})
  target_link_libraries(${name} PRIVATE ${ARG_LIBS} Boost::unit_test_framework ak::warnings)
  if(_ak_boost_test_dyn)
    target_compile_definitions(${name} PRIVATE BOOST_TEST_DYN_LINK)
  endif()
  add_test(NAME ${name} COMMAND ${name} --log_level=test_suite ${ARG_ARGS})
  set_tests_properties(${name} PROPERTIES TIMEOUT 60)
endfunction()

ak_add_test(wire_test         SOURCES wire_test.cpp         LIBS ak::common)
ak_add_test(geneve_test       SOURCES geneve_test.cpp       LIBS ak::oar_net)
ak_add_test(vtep_policy_test  SOURCES vtep_policy_test.cpp  LIBS ak::oar_net)
ak_add_test(mapping_table_test SOURCES mapping_table_test.cpp LIBS ak::oar_net)
ak_add_test(neighbor_test     SOURCES neighbor_test.cpp     LIBS ak::oar_net)
ak_add_test(vswitch_test      SOURCES vswitch_test.cpp      LIBS ak::oar_net)
ak_add_test(oam_test          SOURCES oam_test.cpp          LIBS ak::oar_net)
ak_add_test(vtep_test         SOURCES vtep_test.cpp         LIBS ak::oar_net)
ak_add_test(mtu_test          SOURCES mtu_test.cpp          LIBS ak::oar_net)
ak_add_test(wireguard_test    SOURCES wireguard_test.cpp    LIBS ak::oar_net)
ak_add_test(tunnel_test       SOURCES tunnel_test.cpp       LIBS ak::oar_net)
ak_add_test(xts_cipher_test   SOURCES xts_cipher_test.cpp   LIBS ak::oar_blk)
ak_add_test(key_slot_test     SOURCES key_slot_test.cpp     LIBS ak::oar_blk)
ak_add_test(request_parser_test     SOURCES request_parser_test.cpp     LIBS ak::oar_blk)
ak_add_test(virtio_blk_function_test SOURCES virtio_blk_function_test.cpp LIBS ak::oar_blk)
ak_add_test(virtio_blk_async_test    SOURCES virtio_blk_async_test.cpp    LIBS ak::oar_blk)
ak_add_test(file_backend_test        SOURCES file_backend_test.cpp        LIBS ak::oar_blk)
ak_add_test(net_role_test            SOURCES net_role_test.cpp            LIBS ak::oar_net_role ak::hull)
ak_add_test(blk_role_test            SOURCES blk_role_test.cpp            LIBS ak::oar_blk_role)
ak_add_test(image_manifest_test      SOURCES image_manifest_test.cpp      LIBS ak::oar_blk_image)
ak_add_test(image_volume_test        SOURCES image_volume_test.cpp        LIBS ak::oar_blk_image)
ak_add_test(image_pack_test          SOURCES image_pack_test.cpp          LIBS ak::oar_blk_image)
ak_add_test(sigv4_test               SOURCES sigv4_test.cpp               LIBS ak::oar_blk_s3)
ak_add_test(http_response_test       SOURCES http_response_test.cpp       LIBS ak::oar_blk_s3)
ak_add_test(s3_object_store_test     SOURCES s3_object_store_test.cpp     LIBS ak::oar_blk_s3)
ak_add_test(mailbox_test      SOURCES mailbox_test.cpp      LIBS ak::helm)
ak_add_test(mailbox_device_test SOURCES mailbox_device_test.cpp LIBS ak::helm)
ak_add_test(device_pool_test  SOURCES device_pool_test.cpp  LIBS ak::helm)
ak_add_test(audit_log_test    SOURCES audit_log_test.cpp    LIBS ak::helm)
ak_add_test(command_router_test SOURCES command_router_test.cpp LIBS ak::helm)
ak_add_test(power_sequencer_test SOURCES power_sequencer_test.cpp LIBS ak::helm)
ak_add_test(helm_daemon_test SOURCES helm_daemon_test.cpp LIBS ak::helm ak::harbor_controller ak::hull OpenSSL::Crypto)
ak_add_test(helm_config_test SOURCES helm_config_test.cpp LIBS ak::helm)
ak_add_test(mailbox_bodies_test SOURCES mailbox_bodies_test.cpp LIBS ak::helm)
ak_add_test(mctp_test         SOURCES mctp_test.cpp         LIBS ak::helm)
ak_add_test(signature_verifier_test SOURCES signature_verifier_test.cpp LIBS ak::hull)
ak_add_test(command_auth_test       SOURCES command_auth_test.cpp       LIBS ak::hull)
ak_add_test(mailbox_client_test     SOURCES mailbox_client_test.cpp     LIBS ak::hull)
ak_add_test(vfio_mailbox_test       SOURCES vfio_mailbox_test.cpp       LIBS ak::hull)
ak_add_test(cpu_topology_test       SOURCES cpu_topology_test.cpp       LIBS ak::hull)
ak_add_test(resource_allocator_test SOURCES resource_allocator_test.cpp LIBS ak::hull)

# The jail (hull task 7): jail_test starts jail_probe inside real jails.
# Without user namespaces or Landlock the spawn cases log "skipped" and
# pass; CI also runs the binary under sudo for the privileged path and the
# cgroup placement case.
add_executable(jail_probe jail_probe.cpp)
target_link_libraries(jail_probe PRIVATE ak::warnings)
# The probe runs under Landlock with no /proc access, where the ASan
# runtime cannot start (it reads /proc/self/maps), so it is never
# sanitized or coverage-instrumented; what it checks is the jail, not itself.
if(AK_SANITIZE OR AK_FUZZ)
  target_compile_options(jail_probe PRIVATE -fno-sanitize=all)
  target_link_options(jail_probe PRIVATE -fno-sanitize=all)
endif()
ak_add_test(jail_test SOURCES jail_test.cpp LIBS ak::hull
            ARGS -- $<TARGET_FILE:jail_probe>)
ak_add_test(proto_envelope_test   SOURCES proto_envelope_test.cpp   LIBS ak::proto ak::helm)
ak_add_test(proto_map_update_test SOURCES proto_map_update_test.cpp LIBS ak::proto)
ak_add_test(proto_report_test     SOURCES proto_report_test.cpp     LIBS ak::proto ak::helm)
ak_add_test(proto_link_test       SOURCES proto_link_test.cpp       LIBS ak::proto)
ak_add_test(proto_volume_test     SOURCES proto_volume_test.cpp     LIBS ak::proto)
ak_add_test(proto_hold_wire_test  SOURCES proto_hold_wire_test.cpp  LIBS ak::proto)
ak_add_test(crc32c_test           SOURCES crc32c_test.cpp           LIBS ak::common)
ak_add_test(proto_group_policy_test SOURCES proto_group_policy_test.cpp LIBS ak::proto ak::helm ak::hull)
ak_add_test(group_usage_test SOURCES group_usage_test.cpp LIBS ak::helm)
ak_add_test(proto_vectors_test    SOURCES proto_vectors_test.cpp    LIBS ak::proto ak::hull)
ak_add_test(controller_session_test SOURCES controller_session_test.cpp LIBS ak::helm)
ak_add_test(controller_link_test    SOURCES controller_link_test.cpp    LIBS ak::helm OpenSSL::Crypto)
ak_add_test(harbor_controller_test SOURCES harbor_controller_test.cpp LIBS ak::harbor_controller ak::hull OpenSSL::Crypto)
ak_add_test(key_store_test     SOURCES key_store_test.cpp     LIBS ak::helm)
ak_add_test(virtqueue_test    SOURCES virtqueue_test.cpp    LIBS ak::oar_virtio)
ak_add_test(virtio_pci_test   SOURCES virtio_pci_test.cpp   LIBS ak::oar_virtio)
ak_add_test(oar_protocol_test SOURCES oar_protocol_test.cpp LIBS ak::helm ak::proto)
ak_add_test(oar_link_test     SOURCES oar_link_test.cpp     LIBS ak::helm)
ak_add_test(tunnel_keys_test  SOURCES tunnel_keys_test.cpp  LIBS ak::helm ak::oar_net)
ak_add_test(virtio_function_test SOURCES virtio_function_test.cpp LIBS ak::oar_virtio)
ak_add_test(virtio_net_test   SOURCES virtio_net_test.cpp   LIBS ak::oar_net)

# Python tests for the tooling around the C++ tree (the hull kernel config
# checker). Skipped, not failed, when no interpreter is found.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME kernel_config_test
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/kernel_config_test.py -v)
  set_tests_properties(kernel_config_test PROPERTIES TIMEOUT 60)
endif()

# Kernel Geneve interop (oar-net task 4): the codec against the Linux geneve
# driver in two network namespaces. Needs root, so an ordinary ctest run
# reports it skipped (exit 77); CI runs the script under sudo.
add_executable(geneve_interop_peer geneve_interop_peer.cpp)
target_link_libraries(geneve_interop_peer PRIVATE ak::oar_net ak::warnings)
add_test(NAME geneve_interop
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/geneve_interop.sh $<TARGET_FILE:geneve_interop_peer>)
set_tests_properties(geneve_interop PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)

# Kernel WireGuard interop (oar-net task 10): needs root, so it skips in an
# ordinary ctest run; CI runs tests/wireguard_interop.sh under sudo.
add_executable(wireguard_interop_peer wireguard_interop_peer.cpp)
target_link_libraries(wireguard_interop_peer PRIVATE ak::oar_net ak::warnings)
add_test(NAME wireguard_interop
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/wireguard_interop.sh $<TARGET_FILE:wireguard_interop_peer>)
set_tests_properties(wireguard_interop PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)

# harbor's sample ak-helm configuration must keep parsing.
add_test(NAME ak_helm_check
         COMMAND $<TARGET_FILE:ak-helm> --check ${PROJECT_SOURCE_DIR}/harbor/helm.conf.example)
set_tests_properties(ak_helm_check PROPERTIES TIMEOUT 30)

# helm's mailbox function over vfio-user (helm task 8): the probe serves it
# and harbor/mailbox_smoke.py drives it as a vfio-user client, no root or
# QEMU needed. Only where libvfio-user is built (CI builds without it).
if(AK_HAS_LIBVFIO_USER)
  find_package(Python3 COMPONENTS Interpreter)
  add_executable(mailbox_vfu_probe mailbox_vfu_probe.cpp)
  target_link_libraries(mailbox_vfu_probe PRIVATE ak::helm_vfu ak::warnings)
  if(Python3_Interpreter_FOUND)
    add_test(NAME mailbox_vfu_smoke
      COMMAND sh -c "sock=$(mktemp -u); \"$0\" \"$sock\" & probe=$!; if \"$1\" \"$2\" \"$sock\"; then wait $probe; else kill $probe; exit 1; fi"
              $<TARGET_FILE:mailbox_vfu_probe> ${Python3_EXECUTABLE}
              ${PROJECT_SOURCE_DIR}/harbor/mailbox_smoke.py)
    set_tests_properties(mailbox_vfu_smoke PROPERTIES TIMEOUT 60)
  endif()
endif()
