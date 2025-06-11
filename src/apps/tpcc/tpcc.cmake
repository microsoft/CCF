# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# Small Bank Client executable

add_client_exe(
  tpcc_client SRCS ${CMAKE_CURRENT_LIST_DIR}/clients/tpcc_client.cpp
)
if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 9)
  target_link_libraries(tpcc_client PRIVATE http_parser ccfcrypto)
else()
  target_link_libraries(
    tpcc_client PRIVATE http_parser ccfcrypto c++fs
  )
endif()
# tpcc_client uses http_parser.h, which is an internal header and contains calls
# to LOG_*_FMT functions.
target_compile_definitions(tpcc_client PRIVATE CCF_LOGGER_NO_DEPRECATE)

# tpcc application
add_ccf_app(
  tpcc
  SRCS ${CMAKE_CURRENT_LIST_DIR}/app/tpcc.cpp
  SYSTEM_INCLUDE_DIRS ${CCF_DIR}/3rdparty/test
)

# tpcc unit tests
add_unit_test(tpcc_test ${CMAKE_CURRENT_LIST_DIR}/app/test/tpcc.cpp)

if(BUILD_TESTS)
  set(TPCC_ITERATIONS 50000)

  add_perf_test(
    NAME tpcc
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/tpcc.py
    CLIENT_BIN ./tpcc_client PERF_LABEL TPCC
    ADDITIONAL_ARGS --transactions ${TPCC_ITERATIONS} --max-writes-ahead 250
  )
endif()
