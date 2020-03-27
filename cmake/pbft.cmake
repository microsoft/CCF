# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# PBFT

add_compile_definitions(SIGN_BATCH)
set(SIGN_BATCH ON)

if(SAN)
  add_compile_definitions(USE_STD_MALLOC)
endif()

set(PBFT_SRC
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/global_state.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/client.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/replica.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/commit.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/message.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/reply.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/digest.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/node.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/request.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/checkpoint.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/pre_prepare.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/req_queue.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/prepare.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/status.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/prepared_cert.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/principal.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/log_allocator.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/meta_data.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/data.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/fetch.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/meta_data_cert.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/state.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/libbyz.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/view_change.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/new_view.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/view_change_ack.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/view_info.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/nv_info.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/rep_info.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/rep_info_exactly_once.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/meta_data_d.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/query_stable.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/reply_stable.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/stable_estimator.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/big_req_table.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/pre_prepare_info.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/ledger_writer.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/key_format.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/request_id_gen.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/new_principal.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/network_open.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/append_entries.cpp
)

if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(libbyz.enclave STATIC ${PBFT_SRC})
  target_compile_options(libbyz.enclave PRIVATE -nostdinc)
  target_compile_definitions(
    libbyz.enclave PRIVATE INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
                           __USE_SYSTEM_ENDIAN_H__
  )
  set_property(TARGET libbyz.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(
    libbyz.enclave PRIVATE ${CCF_DIR}/src/ds openenclave::oelibc
                           ${PARSED_ARGS_INCLUDE_DIRS} ${EVERCRYPT_INC}
  )
  use_oe_mbedtls(libbyz.enclave)
  install(
    TARGETS libbyz.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if("virtual" IN_LIST COMPILE_TARGETS)

  add_library(libbyz.host STATIC ${PBFT_SRC})
  target_compile_options(libbyz.host PRIVATE -stdlib=libc++)
  set_property(TARGET libbyz.host PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(libbyz.host PRIVATE SYSTEM ${EVERCRYPT_INC})
  target_link_libraries(libbyz.host PRIVATE secp256k1.host)
  use_client_mbedtls(libbyz.host)
  install(
    TARGETS libbyz.host
    EXPORT ccf
    DESTINATION lib
  )

  add_library(
    libcommontest STATIC
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/network_udp.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/network_udp_mt.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/itimer.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/time_types.cpp
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/statistics.cpp
  )
  target_compile_options(libcommontest PRIVATE -stdlib=libc++)

  target_include_directories(
    libcommontest PRIVATE ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz
                          ${CMAKE_SOURCE_DIR}/3rdparty ${EVERCRYPT_INC}
  )
  target_compile_options(libcommontest PRIVATE -stdlib=libc++)

  add_library(
    libcommontest.mock STATIC
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/mocks/network_mock.cpp
  )
  target_include_directories(
    libcommontest.mock
    PRIVATE ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz
            ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test ${EVERCRYPT_INC}
  )

  target_compile_options(libcommontest.mock PRIVATE -stdlib=libc++)

  function(use_libbyz name)

    target_include_directories(
      ${name}
      PRIVATE ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test
              ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz
              ${CMAKE_SOURCE_DIR}/src/pbft/crypto ${EVERCRYPT_INC}
    )
    target_link_libraries(
      ${name} PRIVATE libbyz.host libcommontest evercrypt.host
                      ${PLATFORM_SPECIFIC_TEST_LIBS}
    )

  endfunction()

  enable_testing()

  function(pbft_add_executable name)
    target_link_libraries(
      ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} secp256k1.host
    )
    use_libbyz(${name})
    add_san(${name})

    target_compile_options(${name} PRIVATE -stdlib=libc++)
    target_link_libraries(
      ${name} PRIVATE -stdlib=libc++ -lc++ -lc++abi secp256k1.host
    )

  endfunction()

  add_executable(
    pbft_replica_test
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/replica_test.cpp
    ${CCF_DIR}/src/enclave/thread_local.cpp
  )
  target_link_libraries(pbft_replica_test PRIVATE ccfcrypto.host)
  pbft_add_executable(pbft_replica_test)

  add_executable(
    pbft_controller_test
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/test_controller_main.cpp
    ${CCF_DIR}/src/enclave/thread_local.cpp
  )
  pbft_add_executable(pbft_controller_test)

  add_executable(
    pbft_client_test
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/client_test.cpp
    ${CCF_DIR}/src/enclave/thread_local.cpp
  )
  pbft_add_executable(pbft_client_test)

  # Unit tests
  add_unit_test(
    ledger_replay_test
    ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/test_ledger_replay.cpp
  )
  target_include_directories(
    ledger_replay_test
    PRIVATE ${CMAKE_SOURCE_DIR}/src/consensus/pbft/libbyz/test/mocks
  )
  target_link_libraries(ledger_replay_test PRIVATE libcommontest.mock)
  use_libbyz(ledger_replay_test)
  add_san(ledger_replay_test)
  set_property(TEST ledger_replay_test PROPERTY LABELS pbft)

  if(EXPERIMENTAL_PBFT_TESTS)
    add_test(
      NAME test_UDP_with_delay
      COMMAND
        python3 ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/e2e_test.py --ip 127.0.0.1
        --servers 4 --clients 2 --test-config
        ${CMAKE_SOURCE_DIR}/tests/infra/libbyz/test_config --with-delays
    )
    set_property(TEST test_UDP_with_delay PROPERTY LABELS pbft)
  endif()
endif()
