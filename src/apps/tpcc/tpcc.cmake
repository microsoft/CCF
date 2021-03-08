# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# Small Bank Client executable

add_client_exe(
  tpcc_client
  SRCS ${CMAKE_CURRENT_LIST_DIR}/clients/tpcc_client.cpp
)
target_link_libraries(
  tpcc_client PRIVATE http_parser.host ccfcrypto.host c++fs
)

# tpcc application
add_ccf_app(tpcc SRCS ${CMAKE_CURRENT_LIST_DIR}/app/tpcc.cpp)
sign_app_library(
  tpcc.enclave ${CMAKE_CURRENT_LIST_DIR}/app/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

if(BUILD_TESTS)

  set(SMALL_BANK_ITERATIONS 200000)

  foreach(CONSENSUS ${CONSENSUSES})
    add_perf_test(
      NAME tpcc
      PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/tpcc_client.py
      CLIENT_BIN ./tpcc_client
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS
        --transactions ${SMALL_BANK_ITERATIONS} --max-writes-ahead 250
    )
  endforeach()
endif()
