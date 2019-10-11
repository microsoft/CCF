# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
cmake_minimum_required(VERSION 3.11)

add_definitions(-DOE_API_VERSION=2)

set(CCF_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include(${CCF_DIR}/cmake/preproject.cmake)

project(ccf C CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common.cmake)

set(TEST_HOST_LOGGING_LEVEL "info")
set(ENV{BETTER_EXCEPTIONS} 1)

option(BUILD_TESTS "Build tests" ON)
option(BUILD_SMALLBANK "Build SmallBank sample app and clients" ON)

# MemberClient executable
add_executable(memberclient src/clients/memberclient.cpp)
use_client_mbedtls(memberclient)
target_link_libraries(memberclient PRIVATE
  ${CMAKE_THREAD_LIBS_INIT}
  ccfcrypto.host
  secp256k1.host
)

# Logging Client executable
add_executable(logging_client src/clients/logging_client.cpp)
use_client_mbedtls(logging_client)
target_link_libraries(logging_client PRIVATE
  ${CMAKE_THREAD_LIBS_INIT}
)

# SNIPPET: Logging application
add_enclave_lib(loggingenc ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/logging/oe_sign.conf ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/sample_key.pem SRCS src/apps/logging/logging.cpp src/apps/logging/stub_for_code_signing.cpp)

if(BUILD_TESTS)
  # Tests
  enable_testing()

  ## Unit tests
  add_unit_test(map_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/map_test.cpp)

  add_unit_test(json_schema
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/json_schema.cpp)

    add_unit_test(logger_json_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/logger_json_test.cpp)

  add_unit_test(kv_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_contention.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kv/test/kv_serialisation.cpp)
  use_client_mbedtls(kv_test)
  target_link_libraries(kv_test PRIVATE
    ${CMAKE_THREAD_LIBS_INIT}
    secp256k1.host)

  add_unit_test(ds_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/ringbuffer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/messaging.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/oversized.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/serializer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/hash.cpp)
  target_link_libraries(ds_test PRIVATE
    ${CMAKE_THREAD_LIBS_INIT})

  add_unit_test(ledger_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/host/test/ledger.cpp)

  if (NOT PBFT)
    add_unit_test(raft_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/raft/test/main.cpp)
    target_link_libraries(raft_test PRIVATE
      ${CRYPTO_LIBRARY})

    add_unit_test(raft_enclave_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/raft/test/enclave.cpp)
    target_include_directories(raft_enclave_test PRIVATE
      ${CCFCRYPTO_INC})
    target_link_libraries(raft_enclave_test PRIVATE
      ${CRYPTO_LIBRARY}
      secp256k1.host)
  endif()

  add_unit_test(crypto_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/test/crypto.cpp)
  target_include_directories(crypto_test PRIVATE
    ${CCFCRYPTO_INC})
  target_link_libraries(crypto_test PRIVATE
    ${CRYPTO_LIBRARY})

   add_unit_test(history_test
     ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/history.cpp)
   target_include_directories(history_test PRIVATE
     ${EVERCRYPT_INC})
   target_link_libraries(history_test PRIVATE
     ${CRYPTO_LIBRARY}
     evercrypt.host
     secp256k1.host)

  add_unit_test(encryptor_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/encryptor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/symmkey.cpp)
  use_client_mbedtls(encryptor_test)
  target_link_libraries(encryptor_test PRIVATE
    secp256k1.host)

  add_unit_test(msgpack_serialization_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/msgpack_serialization.cpp)

  add_unit_test(tls_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/main.cpp)
  target_link_libraries(tls_test PRIVATE
    ${CMAKE_THREAD_LIBS_INIT}
    secp256k1.host)

  add_unit_test(keyexchange_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tls/test/keyexchange.cpp)
  use_client_mbedtls(keyexchange_test)

  add_unit_test(channels_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/node/test/channels.cpp)
  use_client_mbedtls(channels_test)
  target_link_libraries(channels_test PRIVATE secp256k1.host)

  add_unit_test(http_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/enclave/test/http.cpp)
  target_link_libraries(http_test PRIVATE http_parser.host)

  if(NOT PBFT)
    add_unit_test(frontend_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/frontend_test.cpp)
    target_link_libraries(frontend_test PRIVATE
      ${CMAKE_THREAD_LIBS_INIT}
      evercrypt.host
      lua.host
      secp256k1.host)

    add_unit_test(membervoting_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/membervoting_test.cpp)
    target_link_libraries(membervoting_test PRIVATE
      ${CMAKE_THREAD_LIBS_INIT}
      evercrypt.host
      lua.host
      secp256k1.host)

    add_unit_test(nodefrontend_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/node/rpc/test/nodefrontend_test.cpp)
    target_link_libraries(nodefrontend_test PRIVATE
      ${CMAKE_THREAD_LIBS_INIT}
      evercrypt.host
      lua.host
      secp256k1.host)

    if(NOT ENV{RUNTIME_CONFIG_DIR})
      set_tests_properties(membervoting_test PROPERTIES ENVIRONMENT RUNTIME_CONFIG_DIR=${CMAKE_SOURCE_DIR}/src/runtime_config)
    endif()

    add_unit_test(luageneric_test
      ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/luageneric/luageneric_test.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/luageneric/luageneric.cpp)
    target_include_directories(luageneric_test PRIVATE
      ${LUA_DIR})
    target_link_libraries(luageneric_test PRIVATE
      lua.host
      secp256k1.host)
  endif()

  add_unit_test(lua_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/luainterp/test/lua_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/luainterp/test/luakv.cpp)
  target_include_directories(lua_test PRIVATE
    ${LUA_DIR})
  target_link_libraries(lua_test PRIVATE
    lua.host)

  ## Picobench wrapper
  function(add_picobench name)
    add_executable(${name}
      ${ARGN})
    target_include_directories(${name} PRIVATE src)
    # -Wall -Werror catches a number of warnings in picobench
    target_include_directories(${name} SYSTEM PRIVATE 3rdparty)
    add_test(
      NAME ${name}
      COMMAND ${name} --samples=1000)
    use_client_mbedtls(${name})
    target_link_libraries(${name} PRIVATE
      ${CMAKE_THREAD_LIBS_INIT}
    )
    set_property(TEST ${name} PROPERTY LABELS benchmark)
  endfunction()

  ## Picobench benchmarks
  add_picobench(map_bench src/ds/test/map_bench.cpp)
  add_picobench(logger_bench src/ds/test/logger_bench.cpp)
  add_picobench(logger_json_bench src/ds/test/logger_json_bench.cpp)
  add_picobench(json_bench src/ds/test/json_bench.cpp)
  add_picobench(ringbuffer_bench src/ds/test/ringbuffer_bench.cpp)
  target_link_libraries(ringbuffer_bench PRIVATE
    ${CMAKE_THREAD_LIBS_INIT})
  add_picobench(tls_bench src/tls/test/bench.cpp)
  target_link_libraries(tls_bench PRIVATE
    ${CMAKE_THREAD_LIBS_INIT}
    secp256k1.host)
  add_picobench(merkle_bench src/node/test/merkle_bench.cpp)
  target_link_libraries(merkle_bench PRIVATE
    ccfcrypto.host
    evercrypt.host
    secp256k1.host)
  target_include_directories(merkle_bench PRIVATE
    ${EVERCRYPT_INC})
  add_picobench(history_bench src/node/test/history_bench.cpp)
  target_link_libraries(history_bench PRIVATE
    ccfcrypto.host
    evercrypt.host
    secp256k1.host)
  target_include_directories(history_bench PRIVATE
    ${EVERCRYPT_INC})
  add_picobench(kv_bench src/kv/test/kv_bench.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/symmkey.cpp)

  # Merkle Tree memory test
  add_executable(merkle_mem src/node/test/merkle_mem.cpp)
  target_link_libraries(merkle_mem PRIVATE
    ccfcrypto.host
    evercrypt.host
    secp256k1.host
    ${CMAKE_THREAD_LIBS_INIT})
  use_client_mbedtls(merkle_mem)
  target_include_directories(merkle_mem PRIVATE
    ${EVERCRYPT_INC}
    src)

  if (NOT PBFT)
    # Raft driver and scenario test
    add_executable(raft_driver
      ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/raft/test/driver.cpp)
    use_client_mbedtls(raft_driver)
    target_include_directories(raft_driver PRIVATE
      src/raft)
    add_test(
      NAME raft_scenario_test
      COMMAND
        ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/raft_scenarios_runner.py ./raft_driver
          ${CMAKE_SOURCE_DIR}/tests/raft_scenarios ${CMAKE_SOURCE_DIR})
    set_property(TEST raft_scenario_test PROPERTY LABELS raft_scenario)

    if (NOT HTTP)
      ## Member client end to end tests
      add_e2e_test(
        NAME member_client_test
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/memberclient.py
      )

      ## Logging client end to end test
      add_e2e_test(
        NAME logging_client_test
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/loggingclient.py
      )

      if (NOT SAN)
        add_e2e_test(
          NAME connections
          PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/connections.py
        )
      endif()

      ## Storing signed votes test
      add_e2e_test(
        NAME voting_history_test
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/votinghistory.py)

      ## Lua sample app (tx regulator) end to end test
      add_e2e_test(
        NAME lua_txregulator_test
        PYTHON_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/txregulator/tests/txregulatorclient.py
        ADDITIONAL_ARGS
          --app-script ${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/txregulator/app/txregulator.lua
          --datafile ${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/txregulator/dataset/sample_data.csv)

      if(QUOTES_ENABLED)
        add_e2e_test(
          NAME governance_tests
          PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance.py
          ADDITIONAL_ARGS
            --oesign ${OESIGN}
        )

        add_e2e_test(
          NAME reconfiguration_test
          PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/reconfiguration.py
        )

        add_e2e_test(
          NAME code_update_test
          PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/code_update.py
          ADDITIONAL_ARGS
            --oesign ${OESIGN}
            --oeconfpath ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/logging/oe_sign.conf
            --oesignkeypath ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/sample_key.pem
            --election-timeout 1500
        )
      endif()

      add_e2e_test(
        NAME end_to_end_logging
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
      )

      add_e2e_test(
        NAME lua_end_to_end_logging
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
        ADDITIONAL_ARGS
          --app-script ${CMAKE_SOURCE_DIR}/src/apps/logging/logging.lua)

      add_e2e_test(
        NAME end_to_end_scenario
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_scenarios.py
        ADDITIONAL_ARGS
          --scenario ${CMAKE_SOURCE_DIR}/tests/simple_logging_scenario.json
      )

      add_e2e_test(
        NAME election_tests
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/election.py
        ADDITIONAL_ARGS
          --election-timeout 2000
      )

      add_e2e_test(
        NAME recovery_tests
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/recovery.py
        ADDITIONAL_ARGS
          ${RECOVERY_ARGS}
      )

      add_e2e_test(
        NAME schema_tests
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/schema.py
        ADDITIONAL_ARGS
        -p libloggingenc
        --schema-dir ${CMAKE_SOURCE_DIR}/sphinx/source/schemas
        )

      if (BUILD_SMALLBANK)
        include(${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/smallbank/smallbank.cmake)
      endif()

    else()
      add_e2e_test(
        NAME end_to_end_http
        PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_http.py
      )
    endif()

  else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/epbft.cmake)
  endif()

  if (EXTENSIVE_TESTS)
    set_tests_properties(recovery_tests PROPERTIES TIMEOUT 2000)
  endif()
endif()
