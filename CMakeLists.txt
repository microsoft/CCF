# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.11)

set(CCF_DIR ${CMAKE_CURRENT_SOURCE_DIR})

include(${CCF_DIR}/cmake/preproject.cmake)

project(ccf C CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common.cmake)

#find_program(CCACHE_FOUND ccache)
#if(CCACHE_FOUND)
#    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
#    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
#endif(CCACHE_FOUND)

option(DISABLE_PRIMARY_SIGNATURES "Don't have the primary sign batches of state updates." OFF)
if (DISABLE_PRIMARY_SIGNATURES)
  add_definitions(-DDISABLE_PRIMARY_SIGNATURES)
endif()

option(DISABLE_CLIENT_SIGNATURE_VERIFICATION "Accept all client signatures without checking." OFF)
if (DISABLE_CLIENT_SIGNATURE_VERIFICATION)
  add_definitions(-DDISABLE_CLIENT_SIGNATURE_VERIFICATION)
endif()

set(TEST_HOST_LOGGING_LEVEL "info")
set(ENV{BETTER_EXCEPTIONS} 1)

option(BUILD_TESTS "Build tests" ON)

option(NO_COMMITTED_TX_HISTORY "Do not keep tree of hashes of committed transactions" ON)
if(RECORD_TRACE)
  add_definitions(-DNO_COMMITTED_TX_HISTORY)
endif()

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
add_enclave_lib(loggingenc ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/logging/oe_sign.conf ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/sample_key.pem SRCS src/apps/logging/logging.cpp)

if(BUILD_TESTS)
  # Tests
  enable_testing()

  ## Unit tests
  add_unit_test(map_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/map_test.cpp)

  add_unit_test(json_schema
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ds/test/json_schema.cpp)

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

  add_unit_test(raft_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/raft/test/main.cpp)
  target_link_libraries(raft_test PRIVATE
    ${CRYPTO_LIBRARY})

  add_unit_test(ledger_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/host/test/ledger.cpp)

  add_unit_test(raft_enclave_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/raft/test/enclave.cpp)
  target_include_directories(raft_enclave_test PRIVATE
    ${CCFCRYPTO_INC})
  target_link_libraries(raft_enclave_test PRIVATE
    ${CRYPTO_LIBRARY})

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

  if(NOT ENV{RUNTIME_CONFIG_DIR})
    set_tests_properties(membervoting_test PROPERTIES ENVIRONMENT RUNTIME_CONFIG_DIR=${CMAKE_SOURCE_DIR}/src/runtime_config)
  endif()

  add_unit_test(lua_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/luainterp/test/lua_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/luainterp/test/luakv.cpp)
  target_include_directories(lua_test PRIVATE
    ${LUA_DIR})
  target_link_libraries(lua_test PRIVATE
    lua.host)

  add_unit_test(luageneric_test
    ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/luageneric/luageneric_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/apps/luageneric/luageneric.cpp)
  target_include_directories(luageneric_test PRIVATE
    ${LUA_DIR})
  target_link_libraries(luageneric_test PRIVATE
    lua.host
    secp256k1.host)

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
  endfunction()

  ## Picobench benchmarks
  add_picobench(map_bench src/ds/test/map_bench.cpp)
  add_picobench(logger_bench src/ds/test/logger_bench.cpp)
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
    evercrypt.host)
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
    ${CMAKE_THREAD_LIBS_INIT})
    use_client_mbedtls(merkle_mem)
  target_include_directories(merkle_mem PRIVATE
    ${EVERCRYPT_INC}
    src)

  # Raft driver and scenario test
  add_executable(raft_driver
    ${CMAKE_CURRENT_SOURCE_DIR}/src/raft/test/driver.cpp)
  use_client_mbedtls(raft_driver)
  target_include_directories(raft_driver PRIVATE
    src/raft)
  add_test(
     NAME raft_scenario_test
     COMMAND
       ${PYTHON} ${CMAKE_SOURCE_DIR}/tests/raft_scenarios_runner.py ./raft_driver
         ${CMAKE_SOURCE_DIR}/tests/raft_scenarios ${CMAKE_SOURCE_DIR})

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

  ## Storing signed votes test
  add_e2e_test(
    NAME voting_history_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/votinghistory.py)

  ## Lua Logging client end to end test
  add_e2e_test(
    NAME lua_logging_client_test
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/loggingclient.py
    ADDITIONAL_ARGS
      --app-script ${CMAKE_SOURCE_DIR}/src/apps/logging/logging.lua)

  if(QUOTES_ENABLED)
    add_e2e_test(
      NAME quote_verification_test
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/quote_verification.py
    )

    add_e2e_test(
      NAME governance_tests
      PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/governance.py
      ADDITIONAL_ARGS
        --oesign ${OESIGN}
    )
  endif()

  add_e2e_test(
    NAME end_to_end_logging
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging.py
  )

  add_e2e_test(
    NAME end_to_end_scenario
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_scenarios.py
    ADDITIONAL_ARGS
      --scenario ${CMAKE_SOURCE_DIR}/tests/simple_logging_scenario.json
  )

  if (NOT PBFT)
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
  endif()

  if (BUILD_SMALLBANK)
    include(${CMAKE_CURRENT_SOURCE_DIR}/samples/apps/smallbank/smallbank.cmake)
  endif()

  if (EXTENSIVE_TESTS)
    set_tests_properties(recovery_tests PROPERTIES TIMEOUT 2000)
  endif()
endif()
