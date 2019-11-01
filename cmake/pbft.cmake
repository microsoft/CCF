# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# PBFT

add_definitions(-DSIGN_BATCH)
set(SIGN_BATCH ON)

set(PBFT_SRC
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Client.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Replica.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Commit.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Message.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Reply.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Digest.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Node.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Request.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Checkpoint.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Pre_prepare.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Req_queue.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Prepare.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Status.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Prepared_cert.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Principal.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Log_allocator.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Meta_data.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Data.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Fetch.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Meta_data_cert.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/State.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/libbyz.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/View_change.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/New_view.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/View_change_ack.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/View_info.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/NV_info.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Rep_info.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Rep_info_exactly_once.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Meta_data_d.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Query_stable.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Reply_stable.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Stable_estimator.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Big_req_table.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/Pre_prepare_info.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/LedgerWriter.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/LedgerReplay.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/aes_gcm.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/key_format.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/request_id_gen.cpp
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/New_principal.cpp
)

if(NOT ${TARGET} STREQUAL "virtual")
  add_library(libbyz.enclave STATIC ${PBFT_SRC})
  target_compile_options(libbyz.enclave PRIVATE
    -nostdinc
    -U__linux__)
  target_compile_definitions(libbyz.enclave PRIVATE INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD __USE_SYSTEM_ENDIAN_H__ )
  set_property(TARGET libbyz.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(libbyz.enclave PRIVATE
    ${CCF_DIR}/src/ds
    ${OE_INCLUDE_DIR}
    ${OE_LIBCXX_INCLUDE_DIR}
    ${OE_LIBC_INCLUDE_DIR}
    ${OE_TP_INCLUDE_DIR}
    ${PARSED_ARGS_INCLUDE_DIRS}
    ${EVERCRYPT_INC}
  )
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# TODO: For now, this is the only end to end test run with PBFT. When the
# integration is complete, all existing tests will be supported with both
# Raft and PBFT.
add_e2e_test(
    NAME end_to_end_pbft
    PYTHON_SCRIPT ${CMAKE_SOURCE_DIR}/tests/e2e_logging_pbft.py
)

if(${TARGET} STREQUAL "virtual")

  add_library(libbyz.host STATIC ${PBFT_SRC})
  target_compile_options(libbyz.host PRIVATE -stdlib=libc++)
  set_property(TARGET libbyz.host PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(libbyz.host PRIVATE SYSTEM ${EVERCRYPT_INC})

  set(SNMALLOC_ONLY_HEADER_LIBRARY ON)
  add_subdirectory(${CMAKE_SOURCE_DIR}/3rdparty/snmalloc EXCLUDE_FROM_ALL)

  add_library(libcommontest STATIC
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/network_udp.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/network_udp_mt.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/ITimer.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/Time.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/Statistics.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/snmalloc.cpp
  )
  target_compile_options(libcommontest PRIVATE -stdlib=libc++)
  target_link_libraries(libcommontest PRIVATE snmalloc_lib)

  target_include_directories(libcommontest PRIVATE
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz
    ${CMAKE_SOURCE_DIR}/3rdparty
    ${EVERCRYPT_INC}
  )
  target_compile_options(libcommontest PRIVATE -stdlib=libc++)

  add_library(libcommontest.mock STATIC
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/mocks/network_mock.cpp)
  target_link_libraries(libcommontest.mock PRIVATE libcommontest)
  target_include_directories(libcommontest.mock PRIVATE
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test
    ${EVERCRYPT_INC}
  )
  target_compile_options(libcommontest.mock PRIVATE -stdlib=libc++)

  function(use_libbyz name)

    target_include_directories(${name} PRIVATE
      ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test
      ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz
      ${CMAKE_SOURCE_DIR}/src/pbft/crypto
      ${EVERCRYPT_INC}
    )
    target_link_libraries(${name} PRIVATE libbyz.host libcommontest evercrypt.host ${PLATFORM_SPECIFIC_TEST_LIBS})

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
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/replica_main.cpp
  )
  pbft_add_executable(simple-server)

  add_executable(replica-test
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/replica_test.cpp
  )
  pbft_add_executable(replica-test)

  add_executable(test-controller
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/test_controller_main.cpp
  )
  pbft_add_executable(test-controller)

  add_executable(client-test
  ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/client_test.cpp
  )
  pbft_add_executable(client-test)

  ## Unit tests
  add_unit_test(test_ledger_replay
      ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/test_ledger_replay.cpp)
  target_include_directories(test_ledger_replay PRIVATE ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/mocks)
  target_link_libraries(test_ledger_replay PRIVATE libcommontest.mock)
  use_libbyz(test_ledger_replay)
  add_san(test_ledger_replay)

  ## end to end tests
  add_test(
    NAME test_UDP
    COMMAND
      python3 ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/test_config --run-time 30
  )

  add_test(
    NAME test_client_proxy
    COMMAND
      python3 ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 0 --test-config ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/test_config --test-client-proxy
      --run-time 30
  )

  add_test(
    NAME test_UDP_with_delay
    COMMAND
      python3 ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/test_config --with-delays
  )
endif()