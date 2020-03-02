# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# TPCC Client
add_client_exe(tpcc_client
  SRCS ${CMAKE_CURRENT_LIST_DIR}/clients/tpcc_client.cpp
)

target_link_libraries(tpcc_client PRIVATE
  secp256k1.host
  http_parser.host
)

# TPCC Application
add_ccf_app(tpcc SRCS ${CMAKE_CURRENT_LIST_DIR}/app/tpcc.cpp)
sign_app_library(
  tpcc.enclave ${CMAKE_CURRENT_LIST_DIR}/app/oe_sign.conf
  ${CCF_DIR}/src/apps/sample_key.pem
)

# Tests
set(TPCC_VERIFICATION_FILE ${CMAKE_CURRENT_LIST_DIR}/tests/verify_tpcc.json)
set(TPCC_NUM_WAREHOUSES 1)
set(TPCC_ITERATIONS 1)

add_perf_test(
  NAME tpcc_client_test
  PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/tpcc_client.py
  CLIENT_BIN ./tpcc_client
  VERIFICATION_FILE ${TPCC_VERIFICATION_FILE}
  LABEL TPCC
  ADDITIONAL_ARGS --warehouses ${TPCC_NUM_WAREHOUSES} --transactions ${TPCC_ITERATIONS}
)