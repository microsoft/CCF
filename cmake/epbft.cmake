# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# ePBFT

set(PBFT_DIR ${CMAKE_SOURCE_DIR}/ePBFT)

# TODO: For now, this is the only end to end test run with PBFT. When the
# integration is complete, all existing tests will be supported with both
# Raft and PBFT.
add_e2e_test(
    NAME end_to_end_pbft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging_pbft.py
)

if(${TARGET} STREQUAL "virtual")

  set(SNMALLOC_ONLY_HEADER_LIBRARY ON)
  add_subdirectory(${CMAKE_SOURCE_DIR}/3rdparty/snmalloc EXCLUDE_FROM_ALL)

  add_library(libcommon STATIC
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libcommon/network_udp.cpp
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libcommon/network_udp_mt.cpp
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libcommon/ITimer.cpp
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libcommon/Time.cpp
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libcommon/Statistics.cpp
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libcommon/snmalloc.cpp
  )
  target_compile_options(libcommon PRIVATE -stdlib=libc++)
  target_link_libraries(libcommon PRIVATE snmalloc_lib)

  target_include_directories(libcommon PRIVATE
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libbyz
    ${CMAKE_SOURCE_DIR}/3rdparty
    ${EVERCRYPT_INC}
  )
  target_compile_options(libcommon PRIVATE -stdlib=libc++)

  add_library(libcommon.mock STATIC
    ${PBFT_DIR}/src/pbft/libcommon/mocks/network_mock.cpp)
  target_link_libraries(libcommon.mock PRIVATE libcommon)
  target_include_directories(libcommon.mock PRIVATE
    ${PBFT_DIR}/src/pbft/libbyz
    ${PBFT_DIR}/src/pbft/libcommon
    ${EVERCRYPT_INC}
  )
  target_compile_options(libcommon.mock PRIVATE -stdlib=libc++)

  function(use_libbyz name)

    target_include_directories(${name} PRIVATE
      ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/
      ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libcommon
      ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/libbyz
      ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/crypto
      ${EVERCRYPT_INC}
    )
    target_link_libraries(${name} PRIVATE libbyz.host libcommon evercrypt.host ${PLATFORM_SPECIFIC_TEST_LIBS})

  endfunction()

  enable_testing()

  function(pbft_add_executable name)

    target_link_libraries(${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT})
    use_libbyz(${name})
    add_san(${name})

    target_compile_options(${name} PRIVATE -stdlib=libc++)
    target_link_libraries(${name} PRIVATE
        -stdlib=libc++
        -lc++
        -lc++abi)

  endfunction()

  add_executable(simple-server
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/bft-simple/replica_main.cpp
  )
  pbft_add_executable(simple-server)

  add_executable(replica-test
    ${CMAKE_SOURCE_DIR}/ePBFT/src/pbft/bft-simple/test/replica_test.cpp
  )
  pbft_add_executable(replica-test)

  add_executable(test-controller
    ${PBFT_DIR}/src/pbft/bft-simple/test/test_controller_main.cpp
  )
  pbft_add_executable(test-controller)

  add_executable(client-test
    ${PBFT_DIR}/src/pbft/bft-simple/test/client_test.cpp
  )
  pbft_add_executable(client-test)

  ## Unit tests
  add_unit_test(test_ledger_replay
      ${PBFT_DIR}/src/pbft/libbyz/test/test_ledger_replay.cpp)
  target_include_directories(test_ledger_replay PRIVATE ${PBFT_DIR}/src/pbft/libcommon/mocks)
  target_link_libraries(test_ledger_replay PRIVATE libcommon.mock)
  use_libbyz(test_ledger_replay)
  add_san(test_ledger_replay)

  ## end to end tests
  add_test(
    NAME test_UDP
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${PBFT_DIR}/tests/test_config --run-time 30
  )

  add_test(
    NAME test_client_proxy
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 0 --test-config ${PBFT_DIR}/tests/test_config --test-client-proxy
      --run-time 30
  )

  add_test(
    NAME test_UDP_with_delay
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${PBFT_DIR}/tests/test_config --with-delays
  )
endif()