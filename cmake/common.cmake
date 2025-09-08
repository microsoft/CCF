# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

function(add_san_test_properties name)
  if(SAN)
    set_property(
      TEST ${name}
      APPEND
      PROPERTY ENVIRONMENT "ASAN_SYMBOLIZER_PATH=${LLVM_SYMBOLIZER}"
    )
  endif()

  if(TSAN)
    set_property(
      TEST ${name}
      APPEND
      PROPERTY ENVIRONMENT
               "TSAN_OPTIONS=suppressions=${CCF_DIR}/tsan_env_suppressions"
    )

    set_property(
      TEST ${name}
      APPEND
      PROPERTY ENVIRONMENT "TSAN_SYMBOLIZER_PATH=${LLVM_SYMBOLIZER}"
    )
  endif()
endfunction()

# Unit test wrapper
function(add_unit_test name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(
    ${name} PRIVATE src ${CCFCRYPTO_INC} ${CCF_DIR}/3rdparty/test
  )
  enable_coverage(${name})
  target_link_libraries(${name} PRIVATE ${LINK_LIBCXX} ccfcrypto -pthread)
  add_san(${name})

  add_test(NAME ${name} COMMAND ${name})
  set_property(
    TEST ${name}
    APPEND
    PROPERTY LABELS unit
  )

  add_san_test_properties(${name})
endfunction()

# Test binary wrapper
function(add_test_bin name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(
    ${name} PRIVATE src ${CCFCRYPTO_INC} ${CCF_DIR}/3rdparty/test
  )
  enable_coverage(${name})
  target_link_libraries(${name} PRIVATE ${LINK_LIBCXX} ccfcrypto)
  add_san(${name})
endfunction()

# Helper for building end-to-end function tests using the python infrastructure
function(add_e2e_test)
  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS "" "NAME;PYTHON_SCRIPT;LABEL;CURL_CLIENT"
    "CONSTITUTION;ADDITIONAL_ARGS;CONFIGURATIONS"
  )

  if(NOT PARSED_ARGS_CONSTITUTION)
    set(PARSED_ARGS_CONSTITUTION ${CCF_NETWORK_TEST_DEFAULT_CONSTITUTION})
  endif()

  if(BUILD_END_TO_END_TESTS)
    if(PROFILE_TESTS)
      set(PYTHON_WRAPPER
          py-spy
          record
          --format
          speedscope
          -o
          ${PARSED_ARGS_NAME}.trace
          --
          python3
      )
    else()
      set(PYTHON_WRAPPER ${PYTHON})
    endif()

    # For fast e2e runs, tick node faster than default value (except for
    # instrumented builds which may process ticks slower).
    if(SAN)
      set(NODE_TICK_MS 10)
    else()
      set(NODE_TICK_MS 1)
    endif()

    if(NOT PARSED_ARGS_PERF_LABEL)
      set(PARSED_ARGS_PERF_LABEL ${PARSED_ARGS_NAME})
    endif()

    add_test(
      NAME ${PARSED_ARGS_NAME}
      COMMAND
        ${PYTHON_WRAPPER} ${PARSED_ARGS_PYTHON_SCRIPT} -b . --label
        ${PARSED_ARGS_NAME} ${CCF_NETWORK_TEST_ARGS} ${PARSED_ARGS_CONSTITUTION}
        ${PARSED_ARGS_ADDITIONAL_ARGS} --tick-ms ${NODE_TICK_MS}
      CONFIGURATIONS ${PARSED_ARGS_CONFIGURATIONS}
    )

    # Make python test client framework importable
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH}"
    )

    if(SHUFFLE_SUITE)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "SHUFFLE_SUITE=1"
      )
    endif()

    if("${PARSED_ARGS_LABEL}" STREQUAL "partitions")
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1"
      )
    endif()

    add_san_test_properties(${PARSED_ARGS_NAME})

    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS e2e
    )
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS ${PARSED_ARGS_LABEL}
    )

    if(${PARSED_ARGS_CURL_CLIENT})
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "CURL_CLIENT=ON"
      )
    endif()
  endif()
endfunction()

# Helper for building end-to-end perf tests using the python infrastucture
function(add_piccolo_test)

  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS ""
    "NAME;PYTHON_SCRIPT;CONSTITUTION;CLIENT_BIN;PERF_LABEL" "ADDITIONAL_ARGS"
  )

  if(NOT PARSED_ARGS_CONSTITUTION)
    set(PARSED_ARGS_CONSTITUTION ${CCF_NETWORK_TEST_DEFAULT_CONSTITUTION})
  endif()

  set(TEST_NAME "${PARSED_ARGS_NAME}")

  if(NOT PARSED_ARGS_PERF_LABEL)
    set(PARSED_ARGS_PERF_LABEL ${TEST_NAME})
  endif()

  add_test(
    NAME "${PARSED_ARGS_NAME}"
    COMMAND
      ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT} -b . -c ${PARSED_ARGS_CLIENT_BIN}
      ${CCF_NETWORK_TEST_ARGS} ${PARSED_ARGS_CONSTITUTION} --label ${TEST_NAME}
      --perf-label ${PARSED_ARGS_PERF_LABEL} --snapshot-tx-interval 10000
      ${PARSED_ARGS_ADDITIONAL_ARGS} ${NODES}
    CONFIGURATIONS perf
  )

  # Make python test client framework importable
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH}"
  )

  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY LABELS perf
  )

  add_san_test_properties(${TEST_NAME})
endfunction()

# Picobench wrapper
function(add_picobench name)
  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(
    ${name} ${PARSED_ARGS_SRCS} ${CCF_DIR}/src/enclave/thread_local.cpp
  )

  target_include_directories(${name} PRIVATE src ${PARSED_ARGS_INCLUDE_DIRS})

  target_link_libraries(
    ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${PARSED_ARGS_LINK_LIBS}
                    ccfcrypto
  )

  add_san(${name})

  # -Wall -Werror catches a number of warnings in picobench
  target_include_directories(${name} SYSTEM PRIVATE 3rdparty/test)

  add_test(
    NAME ${name}
    COMMAND
      bash -c
      "$<TARGET_FILE:${name}> --samples=1000 --out-fmt=csv --output=${name}.csv && cat ${name}.csv"
  )

  set_property(TEST ${name} PROPERTY LABELS benchmark)

  add_san_test_properties(${name})
endfunction()
