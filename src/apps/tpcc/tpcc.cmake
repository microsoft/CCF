# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# Small Bank Client executable

add_client_exe(
  tpcc_client SRCS ${CMAKE_CURRENT_LIST_DIR}/clients/tpcc_client.cpp
)
target_link_libraries(tpcc_client PRIVATE http_parser.host ccfcrypto.host c++fs)

# tpcc application
add_ccf_app(
  tpcc
  SRCS ${CMAKE_CURRENT_LIST_DIR}/app/tpcc.cpp
  INCLUDE_DIRS ${CCF_DIR}/3rdparty/test
)
sign_app_library(
  tpcc.enclave ${CMAKE_CURRENT_LIST_DIR}/app/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

if(BUILD_TESTS)

  set(TPCC_ITERATIONS 200000)

  # This is currently turned off for BFT because there is some kind of
  # non-determistic execution in the TPCC benchmark.
  # https://github.com/microsoft/CCF/issues/2662
  add_perf_test(
    NAME tpcc
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/tpcc.py
    CLIENT_BIN ./tpcc_client
    CONSENSUS cft
    ADDITIONAL_ARGS --transactions ${TPCC_ITERATIONS} --max-writes-ahead 250
  )
endif()
