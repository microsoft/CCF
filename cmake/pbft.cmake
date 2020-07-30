# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# PBFT

add_compile_definitions(SIGN_BATCH)
set(SIGN_BATCH ON)

if(SAN)
  add_compile_definitions(USE_STD_MALLOC)
endif()

set(PBFT_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/global_state.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/replica.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/commit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/message.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/reply.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/digest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/node.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/request.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/checkpoint.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/pre_prepare.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/req_queue.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/prepare.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/status.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/prepared_cert.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/principal.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/meta_data.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/data.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/fetch.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/meta_data_cert.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/state.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/libbyz.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/view_change.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/new_view.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/view_change_ack.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/view_info.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/nv_info.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/rep_info.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/meta_data_d.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/query_stable.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/reply_stable.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/stable_estimator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/big_req_table.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/pre_prepare_info.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/ledger_writer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/key_format.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/request_id_gen.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/new_principal.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/network_open.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/append_entries.cpp
)

if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(byz.enclave STATIC ${PBFT_SRC})
  target_compile_options(byz.enclave PRIVATE -nostdinc)
  target_compile_definitions(
    byz.enclave PRIVATE INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
                        __USE_SYSTEM_ENDIAN_H__
  )
  set_property(TARGET byz.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(
    byz.enclave PRIVATE ${CCF_DIR}/src/ds ${OE_TARGET_LIBC}
                        ${PARSED_ARGS_INCLUDE_DIRS} ${EVERCRYPT_INC}
  )
  use_oe_mbedtls(byz.enclave)
  install(
    TARGETS byz.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if("virtual" IN_LIST COMPILE_TARGETS)

  add_library(byz.host STATIC ${PBFT_SRC})
  target_compile_options(byz.host PRIVATE -stdlib=libc++)
  set_property(TARGET byz.host PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(byz.host PRIVATE SYSTEM ${EVERCRYPT_INC})
  target_link_libraries(byz.host PRIVATE secp256k1.host)
  use_client_mbedtls(byz.host)
  install(
    TARGETS byz.host
    EXPORT ccf
    DESTINATION lib
  )

  add_library(
    libcommontest STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/test/itimer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/test/time_types.cpp
  )
  target_compile_options(libcommontest PRIVATE -stdlib=libc++)

  target_include_directories(
    libcommontest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz
                          ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty ${EVERCRYPT_INC}
  )
  target_compile_options(libcommontest PRIVATE -stdlib=libc++)

  add_library(
    libcommontest.mock STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/test/mocks/network_mock.cpp
  )
  target_include_directories(
    libcommontest.mock
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz
            ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/test
            ${EVERCRYPT_INC}
  )

  target_compile_options(libcommontest.mock PRIVATE -stdlib=libc++)

  function(use_libbyz name)

    target_include_directories(
      ${name}
      PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/test
              ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz
              ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/crypto ${EVERCRYPT_INC}
    )
    target_link_libraries(
      ${name} PRIVATE byz.host libcommontest evercrypt.host
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
    target_link_libraries(${name} PRIVATE ${LINK_LIBCXX} secp256k1.host)

  endfunction()

  # Unit tests
  add_unit_test(
    replica_unit_tests
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/test/replica_unit_tests.cpp
  )
  target_include_directories(
    replica_unit_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft/libbyz/test/mocks
  )
  target_link_libraries(replica_unit_tests PRIVATE libcommontest.mock)
  use_libbyz(replica_unit_tests)
  add_san(replica_unit_tests)
  set_property(TEST replica_unit_tests PROPERTY LABELS pbft)
endif()
