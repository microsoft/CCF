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

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/pbft.cmake)

configure_file(
  ${CCF_DIR}/src/host/version.h.in ${CCF_GENERATED_DIR}/version.h @ONLY
)

set(CONSENSUSES raft pbft)

option(BUILD_TESTS "Build tests" ON)
option(BUILD_UNIT_TESTS "Build unit tests" ON)
option(TLS_TEST "TLS Test using https://github.com/drwetter/testssl.sh" OFF)
option(BUILD_SMALLBANK "Build SmallBank sample app and clients" ON)

# Build common library for CCF enclaves
add_custom_target(ccf ALL)

if("sgx" IN_LIST COMPILE_TARGETS)
  # enclave version
  add_library(
    ccf.enclave STATIC
    ${CCF_DIR}/src/enclave/main.cpp ${CCF_DIR}/src/enclave/thread_local.cpp
    ${CCF_GENERATED_DIR}/ccf_t.cpp
  )

  target_compile_definitions(
    ccf.enclave PUBLIC INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
  )

  target_compile_options(ccf.enclave PUBLIC -nostdinc -nostdinc++)

  target_include_directories(
    ccf.enclave SYSTEM
    PUBLIC
      "$<BUILD_INTERFACE:${EVERCRYPT_INC}>"
      $<BUILD_INTERFACE:${CCF_GENERATED_DIR}>
      $<INSTALL_INTERFACE:include/3rdparty/hacl-star/evercrypt>
      $<INSTALL_INTERFACE:include/3rdparty/hacl-star/evercrypt/kremlin>
      $<INSTALL_INTERFACE:include/3rdparty/hacl-star/evercrypt/kremlin/kremlib>
  )

  target_link_libraries(
    ccf.enclave
    PUBLIC openenclave::oeenclave
           openenclave::oelibcxx
           openenclave::oelibc
           -static-libgcc
           -lgcc
           ccfcrypto.enclave
           evercrypt.enclave
           http_parser.enclave
           lua.enclave
           secp256k1.enclave
           sss.enclave
           byz.enclave
  )

  set_property(TARGET ccf.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)

  enable_quote_code(ccf.enclave)

  install(
    TARGETS ccf.enclave
    EXPORT ccf
    DESTINATION lib
  )

  add_dependencies(ccf ccf.enclave)
endif()

if("virtual" IN_LIST COMPILE_TARGETS)
  # virtual version
  add_library(
    ccf.virtual STATIC ${CCF_DIR}/src/enclave/main.cpp
                       ${CCF_DIR}/src/enclave/thread_local.cpp
  )

  target_compile_definitions(
    ccf.virtual PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE
                       _LIBCPP_HAS_THREAD_API_PTHREAD
  )

  target_compile_options(ccf.virtual PUBLIC -stdlib=libc++)

  target_include_directories(
    ccf.virtual SYSTEM
    PUBLIC
      "$<BUILD_INTERFACE:${EVERCRYPT_INC}>"
      $<BUILD_INTERFACE:${CCF_GENERATED_DIR}>
      $<INSTALL_INTERFACE:include/3rdparty/hacl-star/evercrypt>
      $<INSTALL_INTERFACE:include/3rdparty/hacl-star/evercrypt/kremlin>
      $<INSTALL_INTERFACE:include/3rdparty/hacl-star/evercrypt/kremlin/kremlib>
  )

  target_link_libraries(
    ccf.virtual
    PUBLIC ${LINK_LIBCXX}
           -static-libgcc
           -lgcc
           ccfcrypto.host
           evercrypt.host
           http_parser.host
           lua.host
           secp256k1.host
           sss.host
           byz.host
           ${CMAKE_THREAD_LIBS_INIT}
  )

  set_property(TARGET ccf.virtual PROPERTY POSITION_INDEPENDENT_CODE ON)

  enable_coverage(ccf.virtual)
  use_client_mbedtls(ccf.virtual)
  add_san(ccf.virtual)

  install(
    TARGETS ccf.virtual
    EXPORT ccf
    DESTINATION lib
  )

  add_dependencies(ccf ccf.virtual)
endif()

install(EXPORT ccf DESTINATION cmake)

# Install all 3rd-party library includes
install(
  DIRECTORY 3rdparty
  DESTINATION include
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

# Install CCF Python infrastructure
install(
  DIRECTORY tests/infra/
  DESTINATION bin/infra
  FILES_MATCHING
  PATTERN "*.py"
  PATTERN "*/__pycache__*" EXCLUDE
)

install(FILES tests/start_network.py DESTINATION bin)
install(FILES tests/requirements.txt DESTINATION bin)

# Create patched alternative of library, to test code version changes
function(create_patched_enclave_lib name app_oe_conf_path enclave_sign_key_path)
  set(enc_name ${name}.enclave)
  if(TARGET ${enc_name})
    set(patched_name ${name}.patched.enclave)
    set(patched_lib_name lib${patched_name}.so)
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${patched_lib_name}
      COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/lib${enc_name}.so
              ${CMAKE_CURRENT_BINARY_DIR}/${patched_lib_name}
      COMMAND PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH} python3
              patch_binary.py -p ${CMAKE_CURRENT_BINARY_DIR}/${patched_lib_name}
      WORKING_DIRECTORY ${CCF_DIR}/tests
      DEPENDS ${enc_name}
    )

    add_custom_target(
      ${patched_name} ALL
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${patched_lib_name}
    )
    sign_app_library(
      ${patched_name} ${app_oe_conf_path} ${enclave_sign_key_path}
    )
  endif()
endfunction()

add_ccf_app(
  logging SRCS src/apps/logging/logging.cpp
               src/apps/logging/stub_for_code_signing.cpp
)
sign_app_library(
  logging.enclave ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/logging/oe_sign.conf
  ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/sample_key.pem
)
create_patched_enclave_lib(
  logging ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/logging/oe_sign.conf
  ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/sample_key.pem
)

set(OE_SIGN_PATH ${OE_BINDIR}/oesign)

if(BUILD_TESTS)
  enable_testing()

  # Unit tests
  if(BUILD_UNIT_TESTS)
    add_unit_test(map_test ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/map_test.cpp)

    add_unit_test(
      json_schema ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/json_schema.cpp
    )

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
    )
    use_client_mbedtls(kv_test)
    target_link_libraries(
      kv_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} secp256k1.host
    )

    add_unit_test(
      ds_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/ring_buffer.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/messaging.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/oversized.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/typed_messages.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/serializer.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/hash.cpp
    )
    target_link_libraries(ds_test PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    add_unit_test(
      ledger_test ${CMAKE_CURRENT_SOURCE_DIR}/src/host/test/ledger.cpp
    )

    add_unit_test(
      raft_test ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/raft/test/main.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/raft/test/term_history.cpp
    )
    target_link_libraries(raft_test PRIVATE ${CRYPTO_LIBRARY})

    add_unit_test(
      raft_enclave_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/raft/test/enclave.cpp
    )
    target_include_directories(raft_enclave_test PRIVATE ${CCFCRYPTO_INC})
    target_link_libraries(
      raft_enclave_test PRIVATE ${CRYPTO_LIBRARY} secp256k1.host
    )

    add_unit_test(
      crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/crypto.cpp
    )
    target_include_directories(crypto_test PRIVATE ${CCFCRYPTO_INC})
    target_link_libraries(crypto_test PRIVATE ${CRYPTO_LIBRARY})

    add_unit_test(
      history_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/history.cpp
    )
    target_include_directories(history_test PRIVATE ${EVERCRYPT_INC})
    target_link_libraries(
      history_test PRIVATE ${CRYPTO_LIBRARY} evercrypt.host secp256k1.host
    )

    add_unit_test(
      secret_sharing_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/secret_share.cpp
    )
    target_link_libraries(secret_sharing_test PRIVATE sss.host)

    add_unit_test(
      encryptor_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/encryptor.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/symmetric_key.cpp
    )
    use_client_mbedtls(encryptor_test)
    target_link_libraries(encryptor_test PRIVATE secp256k1.host)

    add_unit_test(
      historical_queries_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/historical_queries.cpp
    )
    target_link_libraries(historical_queries_test PRIVATE secp256k1.host)

    add_unit_test(
      msgpack_serialization_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/msgpack_serialization.cpp
    )

    add_unit_test(tls_test ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/main.cpp)
    target_link_libraries(
      tls_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} secp256k1.host
    )

    add_unit_test(
      key_exchange_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/key_exchange.cpp
    )
    use_client_mbedtls(key_exchange_test)
    target_link_libraries(key_exchange_test PRIVATE secp256k1.host)

    add_unit_test(
      channels_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/channels.cpp
    )
    use_client_mbedtls(channels_test)
    target_link_libraries(channels_test PRIVATE secp256k1.host)

    add_unit_test(
      http_test ${CMAKE_CURRENT_SOURCE_DIR}/src/http/test/http_test.cpp
    )
    target_link_libraries(http_test PRIVATE http_parser.host)

    add_unit_test(
      frontend_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/frontend_test.cpp
    )
    target_link_libraries(
      frontend_test PRIVATE ${CMAKE_THREAD_LIBS_INIT} evercrypt.host lua.host
                            secp256k1.host http_parser.host sss.host
    )

    add_unit_test(
      tx_status_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/tx_status_test.cpp
    )

    add_unit_test(
      member_voting_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/member_voting_test.cpp
    )
    target_link_libraries(
      member_voting_test
      PRIVATE ${CMAKE_THREAD_LIBS_INIT} evercrypt.host lua.host secp256k1.host
              http_parser.host sss.host
    )

    add_unit_test(
      node_frontend_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/node_frontend_test.cpp
    )
    target_link_libraries(
      node_frontend_test
      PRIVATE ${CMAKE_THREAD_LIBS_INIT} evercrypt.host lua.host secp256k1.host
              http_parser.host sss.host
    )

    if(NOT ENV{RUNTIME_CONFIG_DIR})
      set_tests_properties(
        member_voting_test
        PROPERTIES ENVIRONMENT
                   RUNTIME_CONFIG_DIR=${CMAKE_SOURCE_DIR}/src/runtime_config
      )
    endif()

    add_unit_test(
      lua_generic_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/lua_generic/test/lua_generic_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/lua_generic/lua_generic.cpp
    )
    target_include_directories(lua_generic_test PRIVATE ${LUA_DIR})
    target_link_libraries(
      lua_generic_test PRIVATE lua.host secp256k1.host http_parser.host
    )

    add_unit_test(
      lua_test ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_interp/test/lua_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_interp/test/lua_kv.cpp
    )
    target_include_directories(lua_test PRIVATE ${LUA_DIR})
    target_link_libraries(lua_test PRIVATE lua.host)

    add_unit_test(
      merkle_test ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/merkle_test.cpp
    )

    # Merkle Tree memory test
    add_executable(merkle_mem src/node/test/merkle_mem.cpp)
    target_link_libraries(
      merkle_mem PRIVATE ccfcrypto.host evercrypt.host secp256k1.host
                         ${CMAKE_THREAD_LIBS_INIT}
    )
    use_client_mbedtls(merkle_mem)
    target_include_directories(merkle_mem PRIVATE ${EVERCRYPT_INC} src)

    # Raft driver and scenario test
    add_executable(
      raft_driver
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/raft/test/driver.cpp
    )
    use_client_mbedtls(raft_driver)
    target_include_directories(raft_driver PRIVATE src/raft)

    add_test(
      NAME raft_scenario_test
      COMMAND
        ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/raft_scenarios_runner.py
        ./raft_driver ${CMAKE_SOURCE_DIR}/tests/raft_scenarios
        ${CMAKE_SOURCE_DIR}
    )
    set_property(TEST raft_scenario_test PROPERTY LABELS raft_scenario)
  endif()

  # Picobench benchmarks
  add_picobench(map_bench SRCS src/ds/test/map_bench.cpp)
  add_picobench(logger_bench SRCS src/ds/test/logger_bench.cpp)
  add_picobench(json_bench SRCS src/ds/test/json_bench.cpp)
  add_picobench(ring_buffer_bench SRCS src/ds/test/ring_buffer_bench.cpp)
  add_picobench(
    tls_bench
    SRCS src/tls/test/bench.cpp
    LINK_LIBS secp256k1.host
  )
  add_picobench(
    merkle_bench
    SRCS src/node/test/merkle_bench.cpp
    LINK_LIBS ccfcrypto.host evercrypt.host secp256k1.host
    INCLUDE_DIRS ${EVERCRYPT_INC}
  )
  add_picobench(
    history_bench
    SRCS src/node/test/history_bench.cpp
    LINK_LIBS ccfcrypto.host evercrypt.host secp256k1.host
    INCLUDE_DIRS ${EVERCRYPT_INC}
  )
  add_picobench(
    kv_bench SRCS src/kv/test/kv_bench.cpp src/crypto/symmetric_key.cpp
                  src/enclave/thread_local.cpp
  )
  add_picobench(hash_bench SRCS src/ds/test/hash_bench.cpp)

  # Storing signed governance operations
  add_e2e_test(
    NAME governance_history_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance_history.py
    CONSENSUS raft
    ADDITIONAL_ARGS # https://github.com/microsoft/CCF/issues/1275
                    --ledger-chunk-max-bytes 20MB
  )

  add_e2e_test(
    NAME recovery_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/recovery.py
    CONSENSUS raft
    ADDITIONAL_ARGS
      --recovery
      2
      # Shorten Raft election timeout to speed up test when it kills a node on
      # purpose to check that a recovery network is robust to a view change.
      --raft-election-timeout
      4000
  )

  add_e2e_test(
    NAME rekey_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/rekey.py
    CONSENSUS raft
  )

  add_e2e_test(
    NAME recovery_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    CONSENSUS raft
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
    CONSENSUS raft
    LABEL suite
    ADDITIONAL_ARGS
      --test-duration
      150
      --enforce-reqs
      --test-suite
      reconfiguration
      --raft-election-timeout
      4000
  )

  add_e2e_test(
    NAME full_test_suite
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_suite.py
    CONSENSUS raft
    LABEL suite
    ADDITIONAL_ARGS
      --ledger-recovery-timeout
      20
      --test-duration
      200
      --enforce-reqs
      --test-suite
      all
      --raft-election-timeout
      4000
  )

  add_e2e_test(
    NAME lua_end_to_end_batched
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_batched.py
    CONSENSUS raft
    ADDITIONAL_ARGS --app-script
                    ${CMAKE_SOURCE_DIR}/src/apps/batched/batched.lua
  )

  if(QUOTES_ENABLED)
    add_e2e_test(
      NAME reconfiguration_test
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/reconfiguration.py
      CONSENSUS raft
    )

    add_e2e_test(
      NAME code_update_test
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/code_update.py
      CONSENSUS raft
      ADDITIONAL_ARGS --oesign ${OE_SIGN_PATH} --raft-election-timeout 20000
    )

    add_e2e_test(
      NAME governance_test
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance.py
      CONSENSUS raft
      ADDITIONAL_ARGS --oesign ${OE_SIGN_PATH}
    )
  endif()

  add_e2e_test(
    NAME suspend_nodes_pbft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/suspend_nodes.py
    CONSENSUS pbft
    LABEL long_test
    ADDITIONAL_ARGS --seed 42
  )

  add_e2e_test(
    NAME replay_new_view_pbft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/replay_new_view.py
    CONSENSUS pbft
    LABEL long_test
    ADDITIONAL_ARGS --seed 42
  )

  if(BUILD_SMALLBANK)
    include(${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/smallbank/smallbank.cmake)
  endif()

  if(TLS_TEST)
    add_custom_target(
      testssl ALL
      COMMAND
        test -d testssl || git clone https://github.com/drwetter/testssl.sh
        ${CMAKE_CURRENT_BINARY_DIR}/testssl
    )
  endif()

  foreach(CONSENSUS ${CONSENSUSES})
    # Lua sample app (tx regulator) end to end test
    add_e2e_test(
      NAME lua_txregulator_test_${CONSENSUS}
      PYTHON_SCRIPT
        ${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/txregulator/tests/txregulatorclient.py
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS
        --app-script
        ${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/txregulator/app/txregulator.lua
        --datafile
        ${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/txregulator/dataset/sample_data.csv
    )

    add_e2e_test(
      NAME js_end_to_end_logging_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS --js-app-script
                      ${CMAKE_SOURCE_DIR}/src/apps/logging/logging_js.lua
    )

    add_e2e_test(
      NAME end_to_end_scenario_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_scenarios.py
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS --scenario
                      ${CMAKE_SOURCE_DIR}/tests/simple_logging_scenario.json
    )

    add_e2e_test(
      NAME ws_scaffold_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/ws_scaffold.py
      CONSENSUS ${CONSENSUS}
    )

    add_e2e_test(
      NAME lua_end_to_end_logging_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS --app-script
                      ${CMAKE_SOURCE_DIR}/src/apps/logging/logging.lua
    )

    add_e2e_test(
      NAME member_client_test_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/memberclient.py
      CONSENSUS ${CONSENSUS}
    )

    if(NOT SAN)
      add_e2e_test(
        NAME connections_${CONSENSUS}
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/connections.py
        CONSENSUS ${CONSENSUS}
      )
    endif()

    add_e2e_test(
      NAME receipts_test_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/receipts.py
      CONSENSUS ${CONSENSUS}
    )

    if(TLS_TEST AND ${CONSENSUS} STREQUAL raft)
      add_e2e_test(
        NAME tlstest_${CONSENSUS}
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/tlstest.py
        CONSENSUS ${CONSENSUS}
        LABEL tlstest
      )
    endif()

    add_e2e_test(
      NAME schema_test_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/schema.py
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS -p liblogging --schema-dir
                      ${CMAKE_SOURCE_DIR}/doc/schemas
    )

    add_e2e_test(
      NAME end_to_end_logging_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
      CURL_CLIENT TRUE
      CONSENSUS ${CONSENSUS}
    )

    if(${CONSENSUS} STREQUAL pbft)
      set(ELECTION_TIMEOUT_ARG "--pbft-view-change-timeout" "4000")
    else()
      set(ELECTION_TIMEOUT_ARG "--raft-election-timeout" "4000")
    endif()

    add_e2e_test(
      NAME election_test_${CONSENSUS}
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/election.py
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS ${ELECTION_TIMEOUT_ARG}
    )

  endforeach()

  add_perf_test(
    NAME logging_scenario_perf_test
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/perfclient.py
    CONSENSUS raft
    CLIENT_BIN ./scenario_perf_client
    LABEL log_scenario
    ADDITIONAL_ARGS
      --package
      liblogging
      --scenario-file
      ${CMAKE_CURRENT_LIST_DIR}/tests/perf_logging_scenario_100txs.json
      --max-writes-ahead
      1000
      --repetitions
      1000
  )

  add_perf_test(
    NAME logging_scenario_ws_perf_test
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/infra/perfclient.py
    CONSENSUS raft
    CLIENT_BIN ./scenario_perf_client
    LABEL log_scenario_ws
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
  )
endif()
