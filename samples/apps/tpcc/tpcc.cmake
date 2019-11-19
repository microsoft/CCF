# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# TPCC Application
add_enclave_lib(tpccenc
  ${CMAKE_CURRENT_LIST_DIR}/app/oe_sign.conf
  ${CCF_DIR}/src/apps/sample_key.pem
  SRCS ${CMAKE_CURRENT_LIST_DIR}/app/tpcc.cpp
)