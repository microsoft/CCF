# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
cmake_minimum_required(VERSION 3.11)

set(CCF_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include(${CCF_DIR}/cmake/preproject.cmake)
include(${CCF_DIR}/cmake/version.cmake)

project(
  ccf
  VERSION ${CCF_RELEASE_VERSION}
  LANGUAGES C CXX
)

set(ENV{BETTER_EXCEPTIONS} 1)

message(STATUS "CCF version=${CCF_VERSION}")
message(STATUS "CCF release version=${CCF_RELEASE_VERSION}")

include(${CCF_DIR}/cmake/cpack_settings.cmake)

# Set the default install prefix for CCF. Users may override this value with the
# cmake command. For example:
#
# $ cmake -DCMAKE_INSTALL_PREFIX=/opt/myplace ..
#
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "/opt/${CCF_VERSION}"
      CACHE PATH "Default install prefix" FORCE
  )
endif()

message(STATUS "CMAKE_INSTALL_PREFIX is '${CMAKE_INSTALL_PREFIX}'")

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/preproject.cmake
        DESTINATION cmake
)

include(GNUInstallDirs)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/aft.cmake)

configure_file(
  ${CCF_DIR}/src/host/version.h.in ${CCF_GENERATED_DIR}/version.h @ONLY
)
configure_file(${CCF_DIR}/python/setup.py.in ${CCF_DIR}/python/setup.py @ONLY)

if(ENABLE_BFT)
  set(CONSENSUSES cft bft)
else()
  set(CONSENSUSES cft)
endif()

option(BUILD_TESTS "Build tests" ON)
option(BUILD_UNIT_TESTS "Build unit tests" ON)
option(TLS_TEST "TLS Test using https://github.com/drwetter/testssl.sh" OFF)
option(ZAP_TEST
       "ZAP fuzz test using https://www.zaproxy.org/docs/docker/api-scan/" OFF
)
option(BUILD_SMALLBANK "Build SmallBank sample app and clients" ON)
option(ENABLE_JS_GOV "Enable JS Governance" ON)
if(ENABLE_JS_GOV)
  add_definitions(-DENABLE_JS_GOV)
endif()
option(BUILD_TPCC "Build TPPC sample app and clients" ON)

# Build common library for CCF enclaves
add_custom_target(ccf ALL)

set(CCF_IMPL_SOURCE
    ${CCF_DIR}/src/enclave/main.cpp ${CCF_DIR}/src/enclave/thread_local.cpp
    ${CCF_DIR}/src/js/wrap.cpp
)

if("sgx" IN_LIST COMPILE_TARGETS)
  # enclave version
  add_library(
    ccf.enclave STATIC ${CCF_IMPL_SOURCE} ${CCF_GENERATED_DIR}/ccf_t.cpp
  )

  target_compile_definitions(
    ccf.enclave PUBLIC INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
  )

  target_compile_options(ccf.enclave PUBLIC -nostdinc -nostdinc++)
  add_warning_checks(ccf.enclave)

  target_include_directories(
    ccf.enclave SYSTEM
    PUBLIC
      $<BUILD_INTERFACE:${CCF_GENERATED_DIR}>
      $<INSTALL_INTERFACE:include/ccf/> #< This contains the private headers
                                        #< which are currently under src, and
                                        #< should be removed or renamed
      $<INSTALL_INTERFACE:include/>
      $<INSTALL_INTERFACE:include/3rdparty/>
  )

  target_link_libraries(
    ccf.enclave
    PUBLIC ${OE_TARGET_ENCLAVE_AND_STD}
           -lgcc
           quickjs.enclave
           ccfcrypto.enclave
           http_parser.enclave
           lua.enclave
           aft.enclave
           sss.enclave
           ccf_endpoints.enclave
  )

  set_property(TARGET ccf.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)

  enable_quote_code(ccf.enclave)

  add_lvi_mitigations(ccf.enclave)

  install(
    TARGETS ccf.enclave
    EXPORT ccf
    DESTINATION lib
  )

  add_dependencies(ccf ccf.enclave)
endif()

if("virtual" IN_LIST COMPILE_TARGETS)
  # virtual version
  add_library(ccf.virtual STATIC ${CCF_IMPL_SOURCE})

  target_compile_definitions(
    ccf.virtual PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE
                       _LIBCPP_HAS_THREAD_API_PTHREAD
  )

  target_compile_options(ccf.virtual PUBLIC ${COMPILE_LIBCXX})
  add_warning_checks(ccf.virtual)

  target_include_directories(
    ccf.virtual SYSTEM
    PUBLIC
      $<BUILD_INTERFACE:${CCF_GENERATED_DIR}>
      $<INSTALL_INTERFACE:include/ccf/> #< This contains the private headers
                                        #< which are currently under src, and
                                        #< should be removed or renamed
      $<INSTALL_INTERFACE:include/>
      $<INSTALL_INTERFACE:include/3rdparty/>
  )

  target_link_libraries(
    ccf.virtual
    PUBLIC ${LINK_LIBCXX}
           -lgcc
           ccfcrypto.host
           http_parser.host
           lua.host
           quickjs.host
           aft.virtual
           sss.host
           ccf_endpoints.host
           openenclave::oehost
           ${CMAKE_THREAD_LIBS_INIT}
  )

  set_property(TARGET ccf.virtual PROPERTY POSITION_INDEPENDENT_CODE ON)

  add_san(ccf.virtual)

  install(
    TARGETS ccf.virtual
    EXPORT ccf
    DESTINATION lib
  )

  add_dependencies(ccf ccf.virtual)
endif()

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
)

# Install all CCF headers
install(
  DIRECTORY src/
  DESTINATION include/ccf
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
install(FILES tests/sandbox/sandbox_gov.lua DESTINATION bin)
install(FILES tests/sandbox/sandbox_constitution.js DESTINATION bin)
install(FILES tests/start_network.py DESTINATION bin)
install(FILES tests/requirements.txt DESTINATION bin)

# Generate an ephemeral signing key
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
  COMMAND openssl genrsa -out ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem -3
          3072
)
add_custom_target(
  signing_key ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

# Add Logging app. Rebuilt/redefined here, rather than via add_subdirectory
add_ccf_app(logging SRCS samples/apps/logging/logging.cpp)
sign_app_library(
  logging.enclave ${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/logging/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

# Add NoBuiltins app
add_subdirectory(${CCF_DIR}/samples/apps/nobuiltins)

if(BUILD_TESTS)
  enable_testing()

  # Unit tests
  if(BUILD_UNIT_TESTS)
    add_unit_test(map_test ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/map_test.cpp)

    add_unit_test(
      json_schema ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/json_schema.cpp
    )

    add_unit_test(
      openapi_test ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/openapi.cpp
    )
    target_link_libraries(openapi_test PRIVATE http_parser.host)

    add_unit_test(
      logger_json_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/logger_json_test.cpp
    )
    target_compile_definitions(logger_json_test PUBLIC VERBOSE_LOGGING)

    add_unit_test(
      kv_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_contention.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_serialisation.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_snapshot.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_dynamic_tables.cpp
    )
    target_link_libraries(
      kv_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} http_parser.host
    )

    add_unit_test(
      ds_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/ring_buffer.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/messaging.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/oversized.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/typed_messages.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/serializer.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/hash.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/thread_messaging.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/lru.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/hex.cpp
    )
    target_link_libraries(ds_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_unit_test(
      ledger_test ${CMAKE_CURRENT_SOURCE_DIR}/src/host/test/ledger.cpp
    )

    add_unit_test(
      raft_test ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/main.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/view_history.cpp
    )
    target_link_libraries(raft_test PRIVATE ccfcrypto.host)

    add_unit_test(
      raft_enclave_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/enclave.cpp
    )
    target_include_directories(raft_enclave_test PRIVATE ${CCFCRYPTO_INC})
    target_link_libraries(raft_enclave_test PRIVATE ccfcrypto.host)

    add_unit_test(
      crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/crypto.cpp
    )
    target_include_directories(crypto_test PRIVATE ${CCFCRYPTO_INC})
    target_link_libraries(crypto_test PRIVATE ccfcrypto.host)

    add_unit_test(
      history_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/history.cpp
    )
    target_link_libraries(history_test PRIVATE ccfcrypto.host http_parser.host)

    add_unit_test(
      progress_tracker_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/progress_tracker.cpp
    )
    target_link_libraries(progress_tracker_test PRIVATE ccfcrypto.host)

    add_unit_test(
      secret_sharing_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/secret_share.cpp
    )
    target_link_libraries(secret_sharing_test PRIVATE sss.host)

    add_unit_test(
      encryptor_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/encryptor.cpp
    )
    target_link_libraries(encryptor_test PRIVATE ccfcrypto.host)

    add_unit_test(
      historical_queries_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/historical_queries.cpp
    )
    target_link_libraries(
      historical_queries_test PRIVATE http_parser.host sss.host
    )

    add_unit_test(
      snapshot_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/snapshot.cpp
    )
    target_link_libraries(snapshot_test PRIVATE)

    add_unit_test(
      snapshotter_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/snapshotter.cpp
    )
    target_link_libraries(snapshotter_test PRIVATE)

    add_unit_test(
      msgpack_serialization_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/msgpack_serialization.cpp
    )

    add_unit_test(tls_test ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/main.cpp)
    target_link_libraries(tls_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_test_bin(cert_test ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/cert.cpp)
    target_link_libraries(cert_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_unit_test(
      key_exchange_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/key_exchange.cpp
    )
    target_link_libraries(key_exchange_test PRIVATE)

    add_unit_test(
      channels_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/channels.cpp
    )
    target_link_libraries(channels_test PRIVATE)

    add_unit_test(
      http_test ${CMAKE_CURRENT_SOURCE_DIR}/src/http/test/http_test.cpp
    )
    target_link_libraries(http_test PRIVATE http_parser.host)

    add_unit_test(
      frontend_test ${CMAKE_CURRENT_SOURCE_DIR}/src/js/wrap.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/frontend_test.cpp
    )
    target_link_libraries(
      frontend_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} lua.host http_parser.host
                            sss.host ccf_endpoints.host quickjs.host
    )

    add_unit_test(
      tx_status_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/tx_status_test.cpp
    )

    add_unit_test(
      member_voting_test ${CMAKE_CURRENT_SOURCE_DIR}/src/js/wrap.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/member_voting_test.cpp
    )
    target_link_libraries(
      member_voting_test
      PRIVATE ${CMAKE_THREAD_LIBS_INIT} lua.host http_parser.host sss.host
              ccf_endpoints.host quickjs.host
    )

    set_tests_properties(
      member_voting_test
      PROPERTIES ENVIRONMENT
                 RUNTIME_CONFIG_DIR=${CMAKE_SOURCE_DIR}/src/runtime_config
    )

    add_unit_test(
      proposal_id_test ${CMAKE_CURRENT_SOURCE_DIR}/src/js/wrap.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/proposal_id_test.cpp
    )
    target_link_libraries(
      proposal_id_test
      PRIVATE ${CMAKE_THREAD_LIBS_INIT} lua.host http_parser.host sss.host
              ccf_endpoints.host quickjs.host
    )

    add_unit_test(
      node_frontend_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/node_frontend_test.cpp
    )
    target_link_libraries(
      node_frontend_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} lua.host
                                 http_parser.host sss.host ccf_endpoints.host
    )

    add_unit_test(
      lua_test ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_interp/test/lua_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_interp/test/lua_kv.cpp
    )
    target_include_directories(lua_test PRIVATE ${LUA_DIR})
    target_link_libraries(lua_test PRIVATE lua.host http_parser.host)

    add_unit_test(
      merkle_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/merkle_test.cpp
    )

    # Merkle Tree memory test
    add_executable(merkle_mem src/node/test/merkle_mem.cpp)
    target_compile_options(merkle_mem PRIVATE ${COMPILE_LIBCXX})
    target_link_libraries(
      merkle_mem PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${LINK_LIBCXX} crypto
    )

    # Raft driver and scenario test
    add_executable(
      raft_driver ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/driver.cpp
    )
    target_link_libraries(raft_driver PRIVATE ccfcrypto.host)
    target_include_directories(raft_driver PRIVATE src/aft)

    add_test(
      NAME raft_scenario_test
      COMMAND
        ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/raft_scenarios_runner.py
        ./raft_driver ${CMAKE_SOURCE_DIR}/tests/raft_scenarios
        ${CMAKE_SOURCE_DIR}
    )
    set_property(TEST raft_scenario_test PROPERTY LABELS raft_scenario)

    add_test(NAME csr_test COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/certs.py
                                   ./cert_test
    )
    set_property(
      TEST csr_test
      APPEND
      PROPERTY LABELS unit_test
    )
  endif()

  # Picobench benchmarks
  add_picobench(map_bench SRCS src/ds/test/map_bench.cpp)
  add_picobench(logger_bench SRCS src/ds/test/logger_bench.cpp)
  target_compile_definitions(logger_bench PUBLIC VERBOSE_LOGGING)
  add_picobench(json_bench SRCS src/ds/test/json_bench.cpp)
  add_picobench(ring_buffer_bench SRCS src/ds/test/ring_buffer_bench.cpp)
  add_picobench(
    crypto_bench
    SRCS src/crypto/test/bench.cpp
    LINK_LIBS
  )
  include(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/bench-enclave/crypto_bench.cmake
  )
  add_picobench(history_bench SRCS src/node/test/history_bench.cpp)

  if(LONG_TESTS)
    add_picobench(
      kv_bench SRCS src/kv/test/kv_bench.cpp src/enclave/thread_local.cpp
    )
    add_picobench(merkle_bench SRCS src/node/test/merkle_bench.cpp)
    add_picobench(hash_bench SRCS src/ds/test/hash_bench.cpp)
    add_picobench(digest_bench SRCS src/crypto/test/digest_bench.cpp)
  endif()

  if(ENABLE_JS_GOV)
    set(CONSTITUTION_ARGS
        --constitution ${CCF_DIR}/src/runtime_config/default_actions.js
        --constitution ${CCF_DIR}/src/runtime_config/test_actions.js
        --constitution ${CCF_DIR}/src/runtime_config/constitution.js
    )
    add_e2e_test(
      NAME governance_js_test
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance_js.py
      CONSENSUS cft
      CONSTITUTION ${CONSTITUTION_ARGS}
      ADDITIONAL_ARGS --oe-binary ${OE_BINDIR} --initial-operator-count 1
    )
    set_property(
      TEST governance_js_test
      APPEND
      PROPERTY ENVIRONMENT "JS_GOVERNANCE=ON"
    )
  endif()

  # Storing signed governance operations
  add_e2e_test(
    NAME governance_history_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance_history.py
    CONSENSUS cft
    ADDITIONAL_ARGS
      # Higher snapshot interval as snapshots trigger new ledger chunks, which
      # may result in latest chunk being partially written
      --snapshot-tx-interval 10000
  )

  add_e2e_test(
    NAME recovery_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/recovery.py
    CONSENSUS cft
    ADDITIONAL_ARGS --recovery 3
  )

  add_e2e_test(
    NAME recovery_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    CONSENSUS cft
    LABEL suite
    ADDITIONAL_ARGS
      --test-duration
      150
      --enforce-reqs
      --test-suite
      rekey_recovery
      --test-suite
      membership_recovery
  )

  add_e2e_test(
    NAME reconfiguration_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    CONSENSUS cft
    LABEL suite
    ADDITIONAL_ARGS --test-duration 200 --enforce-reqs --test-suite
                    reconfiguration
  )

  add_e2e_test(
    NAME full_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    CONSENSUS cft
    LABEL suite
    ADDITIONAL_ARGS
      --oe-binary
      ${OE_BINDIR}
      --ledger-recovery-timeout
      20
      --test-duration
      200
      --enforce-reqs
      --test-suite
      all
  )

  if(LONG_TESTS)
    set(ROTATION_TEST_ARGS --rotation-retirements 10 --rotation-suspensions 10)
  endif()

  add_e2e_test(
    NAME rotation_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/rotation.py
    CONSENSUS cft
    LABEL rotation
    ADDITIONAL_ARGS ${ROTATION_TEST_ARGS}
  )

  add_e2e_test(
    NAME committable_suffix_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/committable.py
    CONSENSUS cft
    ADDITIONAL_ARGS --sig-ms-interval 100
  )

  add_e2e_test(
    NAME js_batched_stress_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_batched.py
    CONSENSUS cft
    ADDITIONAL_ARGS
      --js-app-bundle
      ${CMAKE_SOURCE_DIR}/src/apps/batched
      --raft-election-timeout-ms
      10000 # Larger election timeout as recording large JS applications may
            # trigger leadership changes
  )

  add_e2e_test(
    NAME modules_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/js-modules/modules.py
    CONSENSUS cft
    ADDITIONAL_ARGS
      --raft-election-timeout-ms 10000 # Larger election timeout as recording
                                       # large JS applications may trigger
                                       # leadership changes
  )

  add_e2e_test(
    NAME custom_authorization_test
    PYTHON_SCRIPT
      ${CMAKE_SOURCE_DIR}/tests/js-custom-authorization/custom_authorization.py
    CONSENSUS cft
    ADDITIONAL_ARGS --js-app-bundle
                    ${CMAKE_SOURCE_DIR}/tests/js-custom-authorization
  )

  add_e2e_test(
    NAME js_limits_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/js-limits/limits.py
    CONSENSUS cft
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/tests/js-limits
  )

  add_e2e_test(
    NAME authentication_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/js-authentication/authentication.py
    CONSENSUS cft
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/tests/js-authentication
  )

  add_e2e_test(
    NAME content_types_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/js-content-types/content_types.py
    CONSENSUS cft
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/tests/js-content-types
  )

  add_e2e_test(
    NAME governance_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance.py
    CONSENSUS cft
    ADDITIONAL_ARGS --oe-binary ${OE_BINDIR} --initial-operator-count 1
  )

  add_e2e_test(
    NAME governance_no_session_auth_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance.py
    CONSENSUS cft
    ADDITIONAL_ARGS --oe-binary ${OE_BINDIR} --initial-operator-count 1
                    --disable-member-session-auth
  )

  add_e2e_test(
    NAME ca_certs_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/ca_certs.py
    CONSENSUS cft
  )

  add_e2e_test(
    NAME jwt_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/jwt_test.py
    CONSENSUS cft
  )

  add_e2e_test(
    NAME nobuiltins_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/nobuiltins.py
    CONSENSUS cft
    ADDITIONAL_ARGS -p
                    ${CMAKE_BINARY_DIR}/samples/apps/nobuiltins/libnobuiltins
  )

  add_e2e_test(
    NAME reconfiguration_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/reconfiguration.py
    CONSENSUS cft PROPERTY ENVIRONMENT "JS_GOVERNANCE=ON"
  )
  set_property(
    TEST reconfiguration_test
    APPEND
    PROPERTY ENVIRONMENT "JS_GOVERNANCE=ON"
  )

  add_e2e_test(
    NAME code_update_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/code_update.py
    CONSENSUS cft
    ADDITIONAL_ARGS --oe-binary ${OE_BINDIR} --js-app-bundle
                    ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
  )

  if(BUILD_SMALLBANK)
    include(${CMAKE_CURRENT_SOURCE_DIR}/src/apps/smallbank/smallbank.cmake)
  endif()

  if(BUILD_TPCC)
    include(${CMAKE_CURRENT_SOURCE_DIR}/src/apps/tpcc/tpcc.cmake)
  endif()

  if(TLS_TEST)
    add_custom_target(
      testssl ALL
      COMMAND
        test -d testssl || git clone https://github.com/drwetter/testssl.sh
        ${CMAKE_CURRENT_BINARY_DIR}/testssl
    )
  endif()

  add_e2e_test(
    NAME js_e2e_logging_raft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
    CONSENSUS cft
    ADDITIONAL_ARGS --js-app-bundle ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
  )

  add_e2e_test(
    NAME e2e_scenario_raft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_scenarios.py
    CONSENSUS cft
    ADDITIONAL_ARGS --scenario
                    ${CMAKE_SOURCE_DIR}/tests/simple_logging_scenario.json
  )

  add_e2e_test(
    NAME member_client_test_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/memberclient.py
    CONSENSUS cft
  )

  add_e2e_test(
    NAME membership
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/membership.py
    CONSENSUS cft
  )

  add_e2e_test(
    NAME ledger_operation
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/ledger_operation.py
    CONSENSUS cft
  )

  if(NOT SAN)
    # Writing new ledger files and generating new snapshots uses more file
    # descriptors so disable those for this test
    add_e2e_test(
      NAME connections_cft
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/connections.py
      CONSENSUS cft
      ADDITIONAL_ARGS --ledger-chunk-bytes 100Mib --snapshot-tx-interval 10000
    )
  endif()

  if(TLS_TEST)
    add_e2e_test(
      NAME tlstest_cft
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/tlstest.py
      CONSENSUS cft
      LABEL tlstest
    )
  endif()

  if(ZAP_TEST)
    configure_file(
      ${CMAKE_SOURCE_DIR}/tests/zap.config ${CMAKE_BINARY_DIR}/zap.config
      COPYONLY
    )
    add_e2e_test(
      NAME zaptest_cft
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/zap.py
      CONSENSUS cft
      LABEL zaptest
    )
  endif()

  add_e2e_test(
    NAME schema_test_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/schema.py
    CONSENSUS cft
    ADDITIONAL_ARGS -p liblogging --schema-dir ${CMAKE_SOURCE_DIR}/doc/schemas
  )

  add_e2e_test(
    NAME tutorial_cft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_tutorial.py
    CONSENSUS cft
    LABEL tutorial
    CURL_CLIENT TRUE
    ADDITIONAL_ARGS
      -p liblogging --client-tutorial ${CMAKE_SOURCE_DIR}/python/tutorial.py
      --ledger-tutorial ${CMAKE_SOURCE_DIR}/python/ledger_tutorial.py
  )

  add_e2e_sandbox_test(
    NAME forum_app
    SCRIPT ${CMAKE_SOURCE_DIR}/samples/apps/forum/ci.sh
    CONSENSUS cft
    LABEL forum
  )

  foreach(CONSENSUS ${CONSENSUSES})
    add_e2e_test(
      NAME cpp_e2e_logging_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
      CONSENSUS ${CONSENSUS}
    )

    add_e2e_test(
      NAME election_test_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/election.py
      CONSENSUS ${CONSENSUS}
    )

    add_e2e_test(
      NAME vegeta_stress_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/vegeta_stress.py
      CONSENSUS ${CONSENSUS}
      LABEL vegeta
      ADDITIONAL_ARGS -p liblogging
    )

    add_e2e_test(
      NAME vegeta_long_stress_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/vegeta_stress.py
      CONSENSUS ${CONSENSUS}
      LABEL vegeta
      CONFIGURATIONS long_stress
      ADDITIONAL_ARGS -p liblogging --duration 45m
    )

  endforeach()

  add_perf_test(
    NAME ls
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/perfclient.py
    CONSENSUS cft
    CLIENT_BIN ./scenario_perf_client
    ADDITIONAL_ARGS
      --package
      liblogging
      --scenario-file
      ${CMAKE_CURRENT_LIST_DIR}/tests/perf_logging_scenario_100txs.json
      --max-writes-ahead
      1000
      --repetitions
      10000
      --msg-ser-fmt
      msgpack
  )

  add_perf_test(
    NAME ls_ws
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/perfclient.py
    CONSENSUS cft
    CLIENT_BIN ./scenario_perf_client
    ADDITIONAL_ARGS
      --package
      liblogging
      --scenario-file
      ${CMAKE_CURRENT_LIST_DIR}/tests/perf_logging_scenario_100txs.json
      --max-writes-ahead
      1000
      --repetitions
      10000
      --use-websockets
      --msg-ser-fmt
      msgpack
  )

  add_perf_test(
    NAME ls_jwt
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/perfclient.py
    CONSENSUS cft
    CLIENT_BIN ./scenario_perf_client
    ADDITIONAL_ARGS
      --package
      liblogging
      --scenario-file
      ${CMAKE_CURRENT_LIST_DIR}/tests/perf_logging_scenario_100txs.json
      --max-writes-ahead
      1000
      --repetitions
      1000
      --use-jwt
      --msg-ser-fmt
      msgpack
  )

  add_perf_test(
    NAME ls_js
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/perfclient.py
    CONSENSUS cft
    CLIENT_BIN ./scenario_perf_client
    ADDITIONAL_ARGS
      --js-app-bundle
      ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
      --scenario-file
      ${CMAKE_CURRENT_LIST_DIR}/tests/perf_logging_scenario_100txs.json
      --max-writes-ahead
      1000
      --repetitions
      1000
      --msg-ser-fmt
      text
  )

  add_perf_test(
    NAME ls_js_jwt
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/perfclient.py
    CONSENSUS cft
    CLIENT_BIN ./scenario_perf_client
    ADDITIONAL_ARGS
      --js-app-bundle
      ${CMAKE_SOURCE_DIR}/samples/apps/logging/js
      --scenario-file
      ${CMAKE_CURRENT_LIST_DIR}/tests/perf_logging_scenario_100txs.json
      --max-writes-ahead
      1000
      --repetitions
      700
      --use-jwt
      --msg-ser-fmt
      text
  )
endif()

# Generate and install CMake export file for consumers using CMake
include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf-config.cmake.in
  ${CMAKE_BINARY_DIR}/cmake/ccf-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake
  PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_BINDIR CMAKE_INSTALL_INCLUDEDIR
)
write_basic_package_version_file(
  ${CMAKE_BINARY_DIR}/cmake/ccf-config-version.cmake
  COMPATIBILITY SameMajorVersion
)
install(FILES ${CMAKE_BINARY_DIR}/cmake/ccf-config.cmake
              ${CMAKE_BINARY_DIR}/cmake/ccf-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake
)
