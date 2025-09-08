# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
cmake_minimum_required(VERSION 3.21)

set(CCF_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include(${CCF_DIR}/cmake/preproject.cmake)
include(${CCF_DIR}/cmake/version.cmake)

project(
  ${CCF_PROJECT}
  VERSION ${CCF_RELEASE_VERSION}
  DESCRIPTION
    "Build confidential, highly-available distributed systems on top of secure hardware"
  HOMEPAGE_URL "https://github.com/Microsoft/CCF"
  LANGUAGES C CXX
)

message(STATUS "CCF version = ${CCF_VERSION}")
message(STATUS "CCF release version = ${CCF_RELEASE_VERSION}")
message(STATUS "CCF version suffix = ${CCF_VERSION_SUFFIX}")

# Set the default install prefix for CCF. Users may override this value with the
# cmake command. For example:
#
# $ cmake -DCMAKE_INSTALL_PREFIX=/opt/myplace ..
#
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "/opt/${CCF_PROJECT}"
      CACHE PATH "Default install prefix" FORCE
  )
endif()

include(${CCF_DIR}/cmake/cpack_settings.cmake)

message(STATUS "CMAKE_INSTALL_PREFIX is '${CMAKE_INSTALL_PREFIX}'")

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/preproject.cmake
        DESTINATION cmake
)

include(GNUInstallDirs)

# Use fixed name instead of absolute path for reproducible builds
add_compile_options("-ffile-prefix-map=${CCF_DIR}=CCF")

set(CMAKE_MODULE_PATH "${CCF_DIR}/cmake;${CMAKE_MODULE_PATH}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

function(message)
  if(NOT MESSAGE_QUIET)
    _message(${ARGN})
  endif()
endfunction()

option(PROFILE_TESTS "Profile tests" OFF)

if("$ENV{CI}" STREQUAL "")
  set(PYTHON unbuffer python3)
else()
  set(PYTHON python3)
endif()

set(DISTRIBUTE_PERF_TESTS
    ""
    CACHE
      STRING
      "Hosts to which performance tests should be distributed, for example -n ssh://x.x.x.x -n ssh://x.x.x.x -n ssh://x.x.x.x"
)

if(DISTRIBUTE_PERF_TESTS)
  separate_arguments(NODES UNIX_COMMAND ${DISTRIBUTE_PERF_TESTS})
else()
  unset(NODES)
endif()

option(
  VERBOSE_LOGGING
  "Enable verbose, potentially unsafe logging of enclave code. Affects logging level passed at run-time to end-to-end-tests."
  OFF
)
set(TEST_LOGGING_LEVEL "info")
if(VERBOSE_LOGGING)
  set(TEST_LOGGING_LEVEL "trace")
endif()

option(USE_NULL_ENCRYPTOR "Turn off encryption of ledger updates - debug only"
       OFF
)
if(USE_NULL_ENCRYPTOR)
  add_compile_definitions(USE_NULL_ENCRYPTOR)
endif()

option(SAN "Enable Address and Undefined Behavior Sanitizers" OFF)
option(BUILD_END_TO_END_TESTS "Build end to end tests" ON)
option(COVERAGE "Enable coverage mapping" OFF)
option(SHUFFLE_SUITE "Shuffle end to end test suite" OFF)
option(LONG_TESTS "Enable long end-to-end tests" OFF)
option(KV_STATE_RB "Enable RBMap as underlying KV state implementation" OFF)
if(KV_STATE_RB)
  add_compile_definitions(KV_STATE_RB)
endif()

option(USE_SNMALLOC "Link against snmalloc" ON)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/snmalloc.cmake)

# Useful for debugging with libc++ hardening options
option(USE_LIBCXX "Use libc++ instead of libstdc++" OFF)

option(CLANG_TIDY "Run clang-tidy on the codebase" OFF)
# Must happen before tools.cmake is included
if(CLANG_TIDY)
  find_program(
    CLANG_TIDY_EXE NAMES "clang-tidy" "clang-tidy-18" "clang-tidy-15"
  )
  message(STATUS "Using clang-tidy from: ${CLANG_TIDY_EXE}")
endif()

if(SAN OR TSAN)
  find_program(LLVM_SYMBOLIZER NAMES "llvm-symbolizer")
  message(STATUS "Using llvm symbolizer: ${LLVM_SYMBOLIZER}")

  if(USE_SNMALLOC)
    message(FATAL_ERROR "snmalloc cannot be used with SAN or TSAN")
  endif()
endif()

enable_language(ASM)

set(CCF_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
include_directories(${CCF_DIR}/include)
include_directories(${CCF_DIR}/src)

set(CCF_3RD_PARTY_EXPORTED_DIR "${CCF_DIR}/3rdparty/exported")
set(CCF_3RD_PARTY_INTERNAL_DIR "${CCF_DIR}/3rdparty/internal")

include_directories(SYSTEM ${CCF_3RD_PARTY_EXPORTED_DIR})
include_directories(SYSTEM ${CCF_3RD_PARTY_INTERNAL_DIR})

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools.cmake)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools.cmake DESTINATION cmake)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake DESTINATION cmake)

# Copy and install CCF utilities
set(CCF_UTILITIES keygenerator.sh submit_recovery_share.sh)
foreach(UTILITY ${CCF_UTILITIES})
  configure_file(
    ${CCF_DIR}/python/utils/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
  install(PROGRAMS ${CCF_DIR}/python/utils/${UTILITY} DESTINATION bin)
endforeach()

# Copy utilities from tests directory
set(CCF_TEST_UTILITIES tests.sh convert_pico_to_bencher.py test_install.sh
                       docker_wrap.sh config.jinja recovery_benchmark.sh
)
foreach(UTILITY ${CCF_TEST_UTILITIES})
  configure_file(
    ${CCF_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()

# Install additional utilities
install(PROGRAMS ${CCF_DIR}/samples/scripts/snpinfo.sh DESTINATION bin)
install(FILES ${CCF_DIR}/tests/config.jinja DESTINATION bin)

if(SAN)
  install(FILES ${CCF_DIR}/src/san_common.suppressions DESTINATION bin)
endif()

# Install getting_started scripts for VM creation and setup
install(
  DIRECTORY ${CCF_DIR}/getting_started/
  DESTINATION getting_started
  USE_SOURCE_PERMISSIONS
)

set(HTTP_PARSER_SOURCES
    ${CCF_3RD_PARTY_EXPORTED_DIR}/llhttp/api.c
    ${CCF_3RD_PARTY_EXPORTED_DIR}/llhttp/http.c
    ${CCF_3RD_PARTY_EXPORTED_DIR}/llhttp/llhttp.c
)

include(${CCF_DIR}/cmake/crypto.cmake)
include(${CCF_DIR}/cmake/quickjs.cmake)
include(${CCF_DIR}/cmake/qcbor.cmake)
include(${CCF_DIR}/cmake/t_cose.cmake)

# Launcher library
list(APPEND CCF_LAUNCHER_SOURCES ${CCF_DIR}/src/host/run.cpp
     ${CCF_DIR}/src/host/env.cpp
)

add_ccf_static_library(
  ccf_launcher
  SRCS ${CCF_LAUNCHER_SOURCES}
  LINK_LIBS uv
            ${TLS_LIBRARY}
            ${CMAKE_DL_LIBS}
            ${CMAKE_THREAD_LIBS_INIT}
            ${LINK_LIBCXX}
            ccfcrypto
            curl
            http_parser
)

target_include_directories(ccf_launcher PRIVATE ${CCF_GENERATED_DIR})

# HTTP parser
add_library(http_parser "${HTTP_PARSER_SOURCES}")
set_property(TARGET http_parser PROPERTY POSITION_INDEPENDENT_CODE ON)
install(
  TARGETS http_parser
  EXPORT ccf
  DESTINATION lib
)

# CCF js lib
add_ccf_static_library(
  ccf_js
  SRCS ${CCF_DIR}/src/js/global_class_ids.cpp
       ${CCF_DIR}/src/js/core/wrapped_value.cpp
       ${CCF_DIR}/src/js/core/runtime.cpp
       ${CCF_DIR}/src/js/core/context.cpp
       ${CCF_DIR}/src/js/extensions/console.cpp
       ${CCF_DIR}/src/js/extensions/math/random.cpp
       ${CCF_DIR}/src/js/extensions/snp_attestation.cpp
       ${CCF_DIR}/src/js/extensions/ccf/consensus.cpp
       ${CCF_DIR}/src/js/extensions/ccf/converters.cpp
       ${CCF_DIR}/src/js/extensions/ccf/crypto.cpp
       ${CCF_DIR}/src/js/extensions/ccf/gov.cpp
       ${CCF_DIR}/src/js/extensions/ccf/gov_effects.cpp
       ${CCF_DIR}/src/js/extensions/ccf/historical.cpp
       ${CCF_DIR}/src/js/extensions/ccf/host.cpp
       ${CCF_DIR}/src/js/extensions/ccf/kv.cpp
       ${CCF_DIR}/src/js/extensions/ccf/network.cpp
       ${CCF_DIR}/src/js/extensions/ccf/node.cpp
       ${CCF_DIR}/src/js/extensions/ccf/rpc.cpp
       ${CCF_DIR}/src/js/extensions/ccf/request.cpp
       ${CCF_DIR}/src/js/registry.cpp
  LINK_LIBS ccfcrypto quickjs
)

# CCF kv lib
add_ccf_static_library(
  ccf_kv SRCS ${CCF_DIR}/src/kv/tx.cpp ${CCF_DIR}/src/kv/untyped_map_handle.cpp
              ${CCF_DIR}/src/kv/untyped_map_diff.cpp
)

# CCF endpoints lib
add_ccf_static_library(
  ccf_endpoints
  SRCS ${CCF_DIR}/src/endpoints/endpoint.cpp
       ${CCF_DIR}/src/endpoints/endpoint_registry.cpp
       ${CCF_DIR}/src/endpoints/base_endpoint_registry.cpp
       ${CCF_DIR}/src/endpoints/common_endpoint_registry.cpp
       ${CCF_DIR}/src/endpoints/user_endpoint_registry.cpp
       ${CCF_DIR}/src/endpoints/json_handler.cpp
       ${CCF_DIR}/src/endpoints/authentication/cose_auth.cpp
       ${CCF_DIR}/src/endpoints/authentication/cert_auth.cpp
       ${CCF_DIR}/src/endpoints/authentication/empty_auth.cpp
       ${CCF_DIR}/src/endpoints/authentication/jwt_auth.cpp
       ${CCF_DIR}/src/endpoints/authentication/all_of_auth.cpp
       ${CCF_DIR}/src/endpoints/endpoint_utils.cpp
       ${CCF_DIR}/src/indexing/strategies/seqnos_by_key_bucketed.cpp
       ${CCF_DIR}/src/indexing/strategies/seqnos_by_key_in_memory.cpp
       ${CCF_DIR}/src/indexing/strategies/visit_each_entry_in_map.cpp
       ${CCF_DIR}/src/node/historical_queries_adapter.cpp
       ${CCF_DIR}/src/node/historical_queries_utils.cpp
       ${CCF_DIR}/src/node/receipt.cpp
  LINK_LIBS qcbor t_cose http_parser ccfcrypto ccf_kv
)

# CCF task system library
add_ccf_static_library(
  ccf_tasks
  SRCS ${CCF_DIR}/src/tasks/task_system.cpp ${CCF_DIR}/src/tasks/job_board.cpp
       ${CCF_DIR}/src/tasks/ordered_tasks.cpp
)

# Common test args for Python scripts starting up CCF networks
set(WORKER_THREADS
    0
    CACHE STRING "Number of worker threads to start on each CCF node"
)

set(CCF_NETWORK_TEST_DEFAULT_CONSTITUTION
    --constitution
    ${CCF_DIR}/samples/constitutions/default/actions.js
    --constitution
    ${CCF_DIR}/samples/constitutions/default/validate.js
    --constitution
    ${CCF_DIR}/samples/constitutions/default/resolve.js
    --constitution
    ${CCF_DIR}/samples/constitutions/default/apply.js
)
set(CCF_NETWORK_TEST_ARGS --log-level ${TEST_LOGGING_LEVEL} --worker-threads
                          ${WORKER_THREADS}
)

# SNIPPET_START: JS generic application
add_ccf_app(
  js_generic SRCS ${CCF_DIR}/src/apps/js_generic/js_generic.cpp
                  ${CCF_DIR}/samples/apps/main.cpp INSTALL_LIBS ON
)
# SNIPPET_END: JS generic application

install(DIRECTORY ${CCF_DIR}/samples/apps/logging/js
        DESTINATION samples/logging
)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common.cmake)

set(CMAKE_GENERATED_COMMENT
    "This file was auto-generated by CMake from a corresponding *.in file. DO NOT EDIT"
)

configure_file(
  ${CCF_DIR}/src/common/version.h.in ${CCF_DIR}/include/ccf/version.h @ONLY
)
install(FILES ${CCF_DIR}/include/ccf/version.h DESTINATION include/ccf)

file(READ ${CCF_DIR}/doc/host_config_schema/cchost_config.json
     HOST_CONFIG_SCHEMA
)
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS
           ${CCF_DIR}/doc/host_config_schema/cchost_config.json
)
configure_file(
  ${CCF_DIR}/src/host/config_schema.h.in ${CCF_DIR}/src/host/config_schema.h
  @ONLY
)

file(READ ${CCF_DIR}/doc/schemas/gov/2023-06-01-preview/gov.json
     GOV_API_SCHEMA_2023_06_01_PREVIEW
)
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS
           ${CCF_DIR}/doc/schemas/gov/2023-06-01-preview/gov.json
)
file(READ ${CCF_DIR}/doc/schemas/gov/2024-07-01/gov.json
     GOV_API_SCHEMA_2024_07_01
)
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS
           ${CCF_DIR}/doc/schemas/gov/2024-07-01/gov.json
)
configure_file(
  ${CCF_DIR}/src/node/gov/api_schema.h.in ${CCF_DIR}/src/node/gov/api_schema.h
  @ONLY
)

option(BUILD_TESTS "Build tests" ON)
option(BUILD_UNIT_TESTS "Build unit tests" ON)
option(CLIENT_PROTOCOLS_TEST "Test client protocols (TLS, HTTP/2)" OFF)

option(CCF_RAFT_TRACING "Enable tracing of Raft consensus" OFF)
if(CCF_RAFT_TRACING)
  add_compile_definitions(CCF_RAFT_TRACING)
endif()

# Build common library for CCF enclaves
set(CCF_IMPL_SOURCE
    ${CCF_DIR}/src/enclave/main.cpp ${CCF_DIR}/src/enclave/thread_local.cpp
    ${CCF_DIR}/src/node/quote.cpp ${CCF_DIR}/src/node/uvm_endorsements.cpp
)

add_ccf_static_library(
  ccf
  SRCS ${CCF_IMPL_SOURCE}
  LINK_LIBS ${LINK_LIBCXX}
            http_parser
            ccf_js
            ccf_endpoints
            ccfcrypto
            ccf_kv
            nghttp2
            ${CMAKE_THREAD_LIBS_INIT}
            curl
)

target_include_directories(
  ccf SYSTEM
  PUBLIC $<BUILD_INTERFACE:${CCF_GENERATED_DIR}>
         $<INSTALL_INTERFACE:include/ccf/> #< This contains the private headers
                                           #< which are currently under src, and
                                           #< should be removed or renamed
         $<INSTALL_INTERFACE:include/>
         $<INSTALL_INTERFACE:include/3rdparty/>
)

add_dependencies(ccf ccf)

install(
  EXPORT ccf
  DESTINATION cmake
  FILE ccf-targets.cmake
)

# Install exported 3rd-party library includes
install(
  DIRECTORY 3rdparty/exported/
  DESTINATION include/3rdparty
  FILES_MATCHING
  PATTERN "*.h"
  PATTERN "*.hpp"
  PATTERN "*.inc"
)

# Install all private CCF headers, which may still be needed
install(
  DIRECTORY src/
  DESTINATION include/ccf/_private
  FILES_MATCHING
  PATTERN "*.h"
  PATTERN "*/test*" EXCLUDE
)

# Install all public CCF headers
install(
  DIRECTORY include/
  DESTINATION include
  FILES_MATCHING
  PATTERN "*.h"
)

# Install CCF Python infrastructure
install(
  DIRECTORY tests/infra/
  DESTINATION bin/infra
  FILES_MATCHING
  PATTERN "*.py"
  PATTERN "*/__pycache__*" EXCLUDE
)

install(PROGRAMS tests/sandbox/sandbox.sh DESTINATION bin)
install(PROGRAMS tests/docker_wrap.sh DESTINATION bin)
install(PROGRAMS scripts/ensure-snmalloc.sh DESTINATION bin)
install(FILES samples/constitutions/default/actions.js DESTINATION bin)
install(FILES samples/constitutions/default/validate.js DESTINATION bin)
install(FILES samples/constitutions/sandbox/resolve.js DESTINATION bin)
install(FILES samples/constitutions/default/apply.js DESTINATION bin)
install(FILES tests/start_network.py DESTINATION bin)
install(FILES tests/requirements.txt DESTINATION bin)

# Add sample apps
add_subdirectory(${CCF_DIR}/samples)

if(BUILD_TESTS)
  enable_testing()

  # Unit tests
  if(BUILD_UNIT_TESTS)
    add_unit_test(
      snp_ioctl_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/pal/test/snp_ioctl_test.cpp
    )

    add_unit_test(
      snp_attestation_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/pal/test/snp_attestation_validation.cpp
    )

    add_unit_test(map_test ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/map_test.cpp)

    add_unit_test(
      env_test ${CMAKE_CURRENT_SOURCE_DIR}/src/host/test/env.cpp
      ${CCF_DIR}/src/host/env.cpp
    )

    add_unit_test(
      json_schema ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/json_schema.cpp
    )

    add_unit_test(
      logger_test ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/logger.cpp
    )

    add_unit_test(
      openapi_test ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/openapi.cpp
    )
    target_link_libraries(openapi_test PRIVATE http_parser)

    add_unit_test(
      logger_json_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/logger_json_test.cpp
    )

    add_unit_test(
      kv_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_contention.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_serialisation.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_snapshot.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_dynamic_tables.cpp
    )
    target_link_libraries(
      kv_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} http_parser ccf_kv
    )

    add_unit_test(
      ds_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/ring_buffer.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/messaging.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/oversized.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/typed_messages.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/serialized.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/serializer.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/hash.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/thread_messaging.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/lru.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/hex.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/contiguous_set.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/unit_strings.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/dl_list.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/nonstd.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/work_beacon.cpp
    )
    target_link_libraries(ds_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_unit_test(
      task_system_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/tasks/test/basic_tasks.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/tasks/test/ordered_tasks.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/tasks/test/delayed_tasks.cpp
    )
    target_link_libraries(task_system_test PRIVATE ccf_tasks)

    add_unit_test(
      task_system_demo ${CMAKE_CURRENT_SOURCE_DIR}/src/tasks/test/demo/main.cpp
    )
    target_link_libraries(task_system_demo PRIVATE ccf_tasks)

    add_unit_test(
      ledger_test ${CMAKE_CURRENT_SOURCE_DIR}/src/host/test/ledger.cpp
    )

    add_unit_test(
      raft_test ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/main.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/view_history.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/committable_suffix.cpp
    )
    target_link_libraries(raft_test PRIVATE ccfcrypto)

    add_unit_test(
      raft_enclave_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/enclave.cpp
    )
    target_include_directories(raft_enclave_test PRIVATE ${CCFCRYPTO_INC})
    target_link_libraries(raft_enclave_test PRIVATE ccfcrypto)

    add_unit_test(
      crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/crypto.cpp
    )
    target_include_directories(crypto_test PRIVATE ${CCFCRYPTO_INC})
    target_link_libraries(crypto_test PRIVATE ccfcrypto)

    add_unit_test(
      sharing_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/secret_sharing.cpp
    )
    target_include_directories(sharing_test PRIVATE ${CCFCRYPTO_INC})
    target_link_libraries(sharing_test PRIVATE ccfcrypto)

    add_unit_test(
      key_exchange_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/key_exchange.cpp
    )
    target_link_libraries(key_exchange_test PRIVATE)

    add_unit_test(
      history_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/history.cpp
    )
    target_link_libraries(history_test PRIVATE ccfcrypto http_parser ccf_kv)

    add_unit_test(
      encryptor_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/encryptor.cpp
    )
    target_link_libraries(encryptor_test PRIVATE ccfcrypto ccf_kv)

    add_unit_test(js_test ${CMAKE_CURRENT_SOURCE_DIR}/src/js/test/js.cpp)
    target_link_libraries(
      js_test PRIVATE ccf_js ccf_kv ccf_endpoints ccfcrypto http_parser
    )

    add_unit_test(
      endorsements_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/endorsements.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/uvm_endorsements.cpp
    )
    set_property(
      TEST endorsements_test
      APPEND
      PROPERTY
        ENVIRONMENT
        "TEST_ENDORSEMENTS_PATH=${CMAKE_CURRENT_SOURCE_DIR}/tests/uvm_endorsements"
    )

    add_unit_test(
      historical_queries_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/historical_queries.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/receipt.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/receipt.cpp
    )
    target_link_libraries(
      historical_queries_test PRIVATE http_parser ccf_kv ccf_endpoints
    )
    add_unit_test(
      indexing_test ${CMAKE_CURRENT_SOURCE_DIR}/src/indexing/test/indexing.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/indexing/test/lfs.cpp
    )
    target_link_libraries(indexing_test PRIVATE ccf_endpoints ccf_kv)

    add_unit_test(
      snapshot_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/snapshot.cpp
    )
    target_link_libraries(snapshot_test PRIVATE ccf_kv)

    add_unit_test(
      snapshotter_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/snapshotter.cpp
    )
    target_link_libraries(snapshotter_test PRIVATE ccf_kv ccf_endpoints)

    add_unit_test(
      node_info_json_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/node_info_json.cpp
    )

    add_unit_test(tls_test ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/main.cpp)
    target_link_libraries(tls_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_unit_test(
      base64_test ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/base64.cpp
    )
    target_link_libraries(base64_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_unit_test(
      cose_test ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/cose.cpp
    )
    target_link_libraries(
      cose_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} ccfcrypto qcbor
    )

    add_unit_test(pem_test ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/pem.cpp)
    target_link_libraries(pem_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_test_bin(
      kp_cert_test ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/kp_cert.cpp
    )
    target_link_libraries(kp_cert_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_unit_test(
      channels_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/channels.cpp
    )
    target_link_libraries(channels_test PRIVATE)

    add_unit_test(
      http_test ${CMAKE_CURRENT_SOURCE_DIR}/src/http/test/http_test.cpp
    )
    target_link_libraries(http_test PRIVATE http_parser)

    add_unit_test(
      http_etag_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/http/test/http_etag_test.cpp
    )

    add_unit_test(
      frontend_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/frontend_test.cpp
      ${CCF_DIR}/src/node/quote.cpp ${CCF_DIR}/src/node/uvm_endorsements.cpp
    )
    target_link_libraries(
      frontend_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} http_parser ccf_js
                            ccf_endpoints ccfcrypto ccf_kv
    )

    add_unit_test(
      endpoint_registry_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/endpoints/test/endpoint_registry.cpp
    )
    target_include_directories(
      endpoint_registry_test PRIVATE ${CCF_DIR}/src/endpoints
    )
    target_link_libraries(endpoint_registry_test PRIVATE ccf_endpoints)

    add_unit_test(
      jwt_auth_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/endpoints/test/test_jwt_auth.cpp
    )
    target_link_libraries(jwt_auth_test PRIVATE ccf_endpoints)

    add_unit_test(
      tx_status_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/tx_status_test.cpp
    )

    add_unit_test(
      node_frontend_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/node_frontend_test.cpp
      ${CCF_DIR}/src/node/quote.cpp ${CCF_DIR}/src/node/uvm_endorsements.cpp
    )
    target_link_libraries(
      node_frontend_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} http_parser ccf_js
                                 ccf_endpoints ccfcrypto ccf_kv
    )

    add_unit_test(
      merkle_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/merkle_test.cpp
    )

    # Merkle Tree memory test
    add_executable(
      merkle_mem src/node/test/merkle_mem.cpp
                 ${CCF_DIR}/src/enclave/thread_local.cpp
    )
    target_compile_options(merkle_mem PRIVATE ${COMPILE_LIBCXX})
    target_link_libraries(
      merkle_mem PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${LINK_LIBCXX} ccfcrypto
    )

    # Raft driver and scenario test
    add_executable(
      raft_driver ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/driver.cpp
                  src/enclave/thread_local.cpp
    )
    target_link_libraries(raft_driver PRIVATE ccfcrypto)
    target_include_directories(raft_driver PRIVATE src/aft)

    add_test(
      NAME raft_scenario_test
      COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/raft_scenarios_runner.py
              ./raft_driver ${CMAKE_SOURCE_DIR}/tests/raft_scenarios/
    )
    set_property(TEST raft_scenario_test PROPERTY LABELS raft_scenario)

    add_test(NAME csr_test COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/certs.py
                                   ./kp_cert_test
    )
    set_property(
      TEST csr_test
      APPEND
      PROPERTY LABELS unit_test
    )

    add_test(NAME versionifier_test
             COMMAND ${PYTHON}
                     ${CMAKE_SOURCE_DIR}/python/src/ccf/_versionifier.py
    )

    add_test(NAME github_version_lts_test
             COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/infra/github.py
    )
  endif()

  if(NOT TSAN AND NOT USE_LIBCXX)
    # Picobench benchmarks
    add_picobench(map_bench SRCS src/ds/test/map_bench.cpp)
    add_picobench(logger_bench SRCS src/ds/test/logger_bench.cpp)
    add_picobench(json_bench SRCS src/ds/test/json_bench.cpp)
    add_picobench(ring_buffer_bench SRCS src/ds/test/ring_buffer_bench.cpp)
    add_picobench(
      crypto_bench
      SRCS src/crypto/test/bench.cpp
      LINK_LIBS
    )
    add_picobench(
      history_bench
      SRCS src/node/test/history_bench.cpp src/enclave/thread_local.cpp
      LINK_LIBS ccf_kv
    )

    add_picobench(
      kv_bench
      SRCS src/kv/test/kv_bench.cpp src/enclave/thread_local.cpp
      LINK_LIBS ccf_kv
    )
    add_picobench(merkle_bench SRCS src/node/test/merkle_bench.cpp)
    add_picobench(hash_bench SRCS src/ds/test/hash_bench.cpp)

    add_picobench(
      task_bench
      SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/tasks/test/bench/merge_bench.cpp
           ${CMAKE_CURRENT_SOURCE_DIR}/src/tasks/test/bench/sleep_bench.cpp
           ${CMAKE_CURRENT_SOURCE_DIR}/src/tasks/test/bench/contention_bench.cpp
      LINK_LIBS ccf_tasks
    )
  endif()

  if(LONG_TESTS)
    set(ADDITIONAL_RECOVERY_ARGS --with-election --with-unsigned-suffix)
    if(NOT TSAN)
      set(ADDITIONAL_RECOVERY_ARGS ${ADDITIONAL_RECOVERY_ARGS} --with-load)
    endif()
  endif()

  add_e2e_test(
    NAME recovery_test_cft_api_1
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/recovery.py
    ADDITIONAL_ARGS ${ADDITIONAL_RECOVERY_ARGS} --gov-api-version "2024-07-01"
  )

  add_e2e_test(
    NAME recovery_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    LABEL suite
    ADDITIONAL_ARGS
      --test-duration
      300
      --test-suite
      rekey_recovery
      --test-suite
      membership_recovery
      --jinja-templates-path
      ${CMAKE_SOURCE_DIR}/samples/templates
  )

  add_e2e_test(
    NAME reconfiguration_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    LABEL suite
    ADDITIONAL_ARGS
      --test-duration 300 --test-suite reconfiguration --jinja-templates-path
      ${CMAKE_SOURCE_DIR}/samples/templates
  )
  set_property(TEST reconfiguration_test_suite PROPERTY LABELS reconfiguration)

  if(LONG_TESTS)
    add_e2e_test(
      NAME regression_test_suite
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
      LABEL suite
      ADDITIONAL_ARGS --test-duration 300 --test-suite regression_5236
    )
  endif()

  add_e2e_test(
    NAME full_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    LABEL suite
    ADDITIONAL_ARGS
      --ledger-recovery-timeout
      20
      --test-duration
      300
      --test-suite
      all
      --jinja-templates-path
      ${CMAKE_SOURCE_DIR}/samples/templates
  )

  add_e2e_test(
    NAME committable_suffix_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/committable.py
    ADDITIONAL_ARGS --sig-ms-interval 100
  )

  add_e2e_test(
    NAME commit_latency
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/commit_latency.py
    LABEL perf
  )

  add_e2e_test(
    NAME js_batched_stress_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_batched.py
    ADDITIONAL_ARGS
      --js-app-bundle
      ${CMAKE_SOURCE_DIR}/src/apps/batched
      --election-timeout-ms
      10000 # Larger election timeout as recording large JS applications may
            # trigger leadership changes
  )

  add_e2e_test(
    NAME modules_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/js-modules/modules.py
    ADDITIONAL_ARGS
      --package js_generic --election-timeout-ms 10000 # Larger election
      # timeout as recording # large JS applications may trigger leadership
      # changes
  )

  add_e2e_test(
    NAME auth
    PYTHON_SCRIPT
      ${CMAKE_SOURCE_DIR}/tests/js-custom-authorization/custom_authorization.py
    ADDITIONAL_ARGS --package js_generic --js-app-bundle
                    ${CMAKE_SOURCE_DIR}/tests
  )

  add_e2e_test(
    NAME launch_host_process_test
    PYTHON_SCRIPT
      ${CMAKE_SOURCE_DIR}/tests/js-launch-host-process/host_process.py
    ADDITIONAL_ARGS --js-app-bundle
                    ${CMAKE_SOURCE_DIR}/tests/js-launch-host-process
  )

  set(CONSTITUTION_ARGS
      --constitution
      ${CCF_DIR}/samples/constitutions/default/actions.js
      --constitution
      ${CCF_DIR}/samples/constitutions/test/test_actions.js
      --constitution
      ${CCF_DIR}/samples/constitutions/default/validate.js
      --constitution
      ${CCF_DIR}/samples/constitutions/test/resolve.js
      --constitution
      ${CCF_DIR}/samples/constitutions/default/apply.js
  )

  add_e2e_test(
    NAME governance_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance.py
    CONSTITUTION ${CONSTITUTION_ARGS}
    ADDITIONAL_ARGS --initial-operator-count 1 --jinja-templates-path
                    ${CMAKE_SOURCE_DIR}/samples/templates
  )

  add_e2e_test(
    NAME jwt_test PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/jwt_test.py
  )

  add_e2e_test(
    NAME code_update_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/code_update.py
    ADDITIONAL_ARGS
      --js-app-bundle
      ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
      --constitution
      ${CMAKE_SOURCE_DIR}/samples/constitutions/virtual/virtual_attestation_actions.js
  )

  if(CLIENT_PROTOCOLS_TEST)
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/testssl/testssl.sh
      COMMAND
        rm -rf ${CMAKE_CURRENT_BINARY_DIR}/testssl && git clone --depth 1
        --branch v3.2rc4 --single-branch -c advice.detachedHead=false
        https://github.com/drwetter/testssl.sh
        ${CMAKE_CURRENT_BINARY_DIR}/testssl
    )
    add_custom_target(
      testssl ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/testssl/testssl.sh
    )
  endif()

  add_e2e_test(
    NAME e2e_logging_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
  )

  set(RBAC_CONSTITUTION_ARGS
      --constitution
      ${CCF_DIR}/samples/constitutions/default/actions.js
      --constitution
      ${CCF_DIR}/samples/constitutions/roles/set_role_definition.js
      --constitution
      ${CCF_DIR}/samples/constitutions/default/validate.js
      --constitution
      ${CCF_DIR}/samples/constitutions/default/resolve.js
      --constitution
      ${CCF_DIR}/samples/constitutions/default/apply.js
  )

  add_e2e_test(
    NAME programmability
    CONSTITUTION ${RBAC_CONSTITUTION_ARGS}
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/programmability.py
  )

  # This test uses large requests (so too slow for SAN)
  if(NOT SAN)
    add_e2e_test(
      NAME e2e_limits PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/limits.py
    )
  endif()

  add_e2e_test(
    NAME e2e_redirects
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/redirects.py
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
  )

  add_e2e_test(
    NAME e2e_logging_http2
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
                    --http2
  )

  add_e2e_test(
    NAME membership_api_1
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/membership.py
    ADDITIONAL_ARGS --gov-api-version "2024-07-01"
  )

  add_e2e_test(
    NAME partitions_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/partitions_test.py
    LABEL partitions
    CONFIGURATIONS partitions
  )

  execute_process(
    COMMAND "cat" "/etc/os-release"
    COMMAND "grep" "^NAME="
    COMMAND "cut" "-d" "=" "-f" "2"
    COMMAND "tr" "-d" "\""
    OUTPUT_VARIABLE "OS_RELEASE"
    RESULT_VARIABLE RETURN_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT RETURN_CODE STREQUAL "0")
    message(FATAL_ERROR "Error calling cat /etc/os-release")
  endif()
  message(STATUS "OS_RELEASE = ${OS_RELEASE}")
  if(OS_RELEASE STREQUAL "Microsoft Azure Linux")
    set_property(
      TEST partitions_cft
      APPEND
      PROPERTY ENVIRONMENT "XTABLES_LIBDIR=/usr/lib/iptables"
    )
  endif()

  add_e2e_test(
    NAME connections_cft PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/connections.py
  )

  add_e2e_test(
    NAME consistency_trace_validation
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/consistency_trace_validation.py
  )

  add_e2e_test(
    NAME fuzz_test PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/fuzzing.py
  )

  if(CLIENT_PROTOCOLS_TEST)
    add_e2e_test(
      NAME client_protocols
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/client_protocols.py
      LABEL protocolstest
    )
  endif()

  add_e2e_test(
    NAME schema_test_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/schema.py
    ADDITIONAL_ARGS
      --schema-dir
      ${CMAKE_SOURCE_DIR}/doc/schemas
      --ledger-tutorial
      ${CMAKE_SOURCE_DIR}/python/ledger_tutorial.py
      --config-samples-dir
      ${CMAKE_SOURCE_DIR}/samples/config
      --historical-testdata
      ${CMAKE_SOURCE_DIR}/tests/testdata
  )

  list(APPEND LTS_TEST_ARGS --ccf-version ${CCF_VERSION})
  if(LONG_TESTS)
    list(APPEND LTS_TEST_ARGS --check-ledger-compatibility)
  endif()

  if(NOT SAN)
    add_e2e_test(
      NAME lts_compatibility
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/lts_compatibility.py
      LABEL e2e
      ADDITIONAL_ARGS
        ${LTS_TEST_ARGS}
        --constitution
        ${CMAKE_SOURCE_DIR}/samples/constitutions/virtual/virtual_attestation_actions.js
    )
    set_property(
      TEST lts_compatibility
      APPEND
      PROPERTY ENVIRONMENT "LTS_COMPAT_GOV_CLIENT=1"
    )
    set_property(
      TEST lts_compatibility
      APPEND
      PROPERTY LABELS lts_compatibility
    )
  endif()

  if(LONG_TESTS)
    set(ROTATION_TEST_ARGS --rotation-retirements 10)
  endif()

  add_e2e_test(
    NAME rotation_test_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/rotation.py
    LABEL rotation
    ADDITIONAL_ARGS ${ROTATION_TEST_ARGS}
  )

  set(RECONFIG_TEST_ARGS --ccf-version ${CCF_VERSION})
  add_e2e_test(
    NAME reconfiguration_test_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/reconfiguration.py
    ADDITIONAL_ARGS ${RECONFIG_TEST_ARGS}
  )
  set_property(TEST reconfiguration_test_cft PROPERTY LABELS reconfiguration)

  add_e2e_test(
    NAME election_test PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/election.py
  )

  if(LONG_TESTS)
    add_e2e_test(
      NAME acme_endorsement_test
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/acme_endorsement.py
      LABEL ACME
    )
  endif()

  add_piccolo_test(
    NAME pi_ls
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/piccolo_driver.py
    CLIENT_BIN ./submit PERF_LABEL "Logging"
    ADDITIONAL_ARGS --package "samples/apps/logging/logging" --max-writes-ahead
                    1000 --repetitions 100000
  )

  add_piccolo_test(
    NAME pi_basic
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/basicperf.py
    CLIENT_BIN ./submit PERF_LABEL "Basic"
    ADDITIONAL_ARGS --package "samples/apps/basic/basic" --client-def
                    "1,write,3000000,primary"
  )

  add_piccolo_test(
    NAME pi_basic_js
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/basicperf.py
    CLIENT_BIN ./submit PERF_LABEL "Basic JS"
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/samples/apps/basic/js
                    --client-def "1,write,300000,primary"
  )

  if(WORKER_THREADS)
    add_piccolo_test(
      NAME pi_basic_mt
      PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/basicperf.py
      CLIENT_BIN ./submit PERF_LABEL "Basic Multi-Threaded"
      ADDITIONAL_ARGS --package "samples/apps/basic/basic" --client-def
                      "${WORKER_THREADS},write,2000000,primary"
    )
  endif()

  add_piccolo_test(
    NAME pi_ls_jwt
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/piccolo_driver.py
    CLIENT_BIN ./submit PERF_LABEL "Logging JWT"
    ADDITIONAL_ARGS
      --package
      "samples/apps/logging/logging"
      --max-writes-ahead
      1000
      --repetitions
      10000
      --use-jwt
  )
  add_test_bin(
    curl_test ${CMAKE_CURRENT_SOURCE_DIR}/src/http/test/curl_test.cpp
  )
  target_link_libraries(curl_test PRIVATE curl uv http_parser)

  if(LONG_TESTS)
    add_e2e_test(
      NAME e2e_curl PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_curl.py
    )
  endif()
endif()

# Generate and install CMake export file for consumers using CMake
include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/${CCF_PROJECT}-config.cmake.in
  ${CMAKE_BINARY_DIR}/cmake/${CCF_PROJECT}-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake
  PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_BINDIR CMAKE_INSTALL_INCLUDEDIR
)
write_basic_package_version_file(
  ${CMAKE_BINARY_DIR}/cmake/${CCF_PROJECT}-config-version.cmake
  COMPATIBILITY SameMajorVersion
)
install(
  FILES ${CMAKE_BINARY_DIR}/cmake/${CCF_PROJECT}-config.cmake
        ${CMAKE_BINARY_DIR}/cmake/${CCF_PROJECT}-config-version.cmake
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cpack_ccfapp.cmake
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cpack_versions_pin.cmake
  DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake
)

if(NOT USE_LIBCXX)
  # Perf tool executable
  include(${CCF_DIR}/tests/perf-system/submitter/CMakeLists.txt)
endif()
