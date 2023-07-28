# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Unit test wrapper
function(add_unit_test name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(
    ${name} PRIVATE src ${CCFCRYPTO_INC} ${CCF_DIR}/3rdparty/test
  )
  enable_coverage(${name})
  target_link_libraries(${name} PRIVATE ${LINK_LIBCXX} ccfcrypto.host -pthread)
  link_openenclave_host(${name})
  add_san(${name})

  add_test(NAME ${name} COMMAND ${name})
  set_property(
    TEST ${name}
    APPEND
    PROPERTY LABELS unit_test
  )

  set_property(
    TEST ${name}
    APPEND
    PROPERTY ENVIRONMENT
             "TSAN_OPTIONS=suppressions=${CCF_DIR}/tsan_env_suppressions"
  )

  # https://github.com/microsoft/CCF/issues/5198
  set_property(
    TEST ${name}
    APPEND
    PROPERTY ENVIRONMENT "ASAN_OPTIONS=alloc_dealloc_mismatch=0"
  )

endfunction()

# Test binary wrapper
function(add_test_bin name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(${name} PRIVATE src ${CCFCRYPTO_INC})
  enable_coverage(${name})
  target_link_libraries(${name} PRIVATE ${LINK_LIBCXX} ccfcrypto.host)
  add_san(${name})
endfunction()

# Helper for building clients inheriting from perf_client
function(add_client_exe name)

  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_link_libraries(
    ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} ccfcrypto.host
  )
  target_include_directories(
    ${name} PRIVATE ${CCF_DIR}/src/clients/perf ${PARSED_ARGS_INCLUDE_DIRS}
  )

endfunction()

# Helper for building end-to-end function tests using the python infrastructure
function(add_e2e_test)
  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS "" "NAME;PYTHON_SCRIPT;LABEL;CURL_CLIENT;"
    "CONSTITUTION;ADDITIONAL_ARGS;CONFIGURATIONS;CONTAINER_NODES"
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

    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY ENVIRONMENT
               "TSAN_OPTIONS=suppressions=${CCF_DIR}/tsan_env_suppressions"
    )

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
    if((${PARSED_ARGS_CONTAINER_NODES}) AND (LONG_TESTS))
      # Containerised nodes are only enabled with long tests
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "CONTAINER_NODES=ON"
      )
    endif()

    if(DEFINED DEFAULT_ENCLAVE_TYPE)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "DEFAULT_ENCLAVE_TYPE=${DEFAULT_ENCLAVE_TYPE}"
      )
    endif()

    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY ENVIRONMENT "DEFAULT_ENCLAVE_PLATFORM=${COMPILE_TARGET}"
    )
  endif()
endfunction()

# Helper for building end-to-end perf tests using the python infrastucture
function(add_perf_test)

  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS ""
    "NAME;PYTHON_SCRIPT;CONSTITUTION;CLIENT_BIN;VERIFICATION_FILE;LABEL"
    "ADDITIONAL_ARGS"
  )

  if(NOT PARSED_ARGS_CONSTITUTION)
    set(PARSED_ARGS_CONSTITUTION ${CCF_NETWORK_TEST_DEFAULT_CONSTITUTION})
  endif()

  if(PARSED_ARGS_VERIFICATION_FILE)
    set(VERIFICATION_ARG "--verify ${PARSED_ARGS_VERIFICATION_FILE}")
  else()
    unset(VERIFICATION_ARG)
  endif()

  set(TESTS_SUFFIX "")
  set(ENCLAVE_TYPE "")
  set(ENCLAVE_PLATFORM "${COMPILE_TARGET}")
  if("sgx" STREQUAL COMPILE_TARGET)
    set(TESTS_SUFFIX "${TESTS_SUFFIX}_sgx")
    set(ENCLAVE_TYPE "release")
  elseif("virtual" STREQUAL COMPILE_TARGET)
    set(TESTS_SUFFIX "${TESTS_SUFFIX}_virtual")
    set(ENCLAVE_TYPE "virtual")
  endif()

  set(TESTS_SUFFIX "${TESTS_SUFFIX}_cft")

  set(TEST_NAME "${PARSED_ARGS_NAME}${TESTS_SUFFIX}")

  set(LABEL_ARG "${TEST_NAME}^")

  add_test(
    NAME "${PARSED_ARGS_NAME}${TESTS_SUFFIX}"
    COMMAND
      ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT} -b . -c ${PARSED_ARGS_CLIENT_BIN}
      ${CCF_NETWORK_TEST_ARGS} ${PARSED_ARGS_CONSTITUTION} --write-tx-times
      ${VERIFICATION_ARG} --label ${LABEL_ARG} --snapshot-tx-interval 10000
      ${PARSED_ARGS_ADDITIONAL_ARGS} -e ${ENCLAVE_TYPE} -t ${ENCLAVE_PLATFORM}
      ${NODES}
  )

  # Make python test client framework importable
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH}"
  )
  if(DEFINED DEFAULT_ENCLAVE_TYPE)
    set_property(
      TEST ${TEST_NAME}
      APPEND
      PROPERTY ENVIRONMENT "DEFAULT_ENCLAVE_TYPE=${DEFAULT_ENCLAVE_TYPE}"
    )
  endif()
  if(DEFINED DEFAULT_ENCLAVE_PLATFORM)
    set_property(
      TEST ${TEST_NAME}
      APPEND
      PROPERTY ENVIRONMENT
               "DEFAULT_ENCLAVE_PLATFORM=${DEFAULT_ENCLAVE_PLATFORM}"
    )
  endif()
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY LABELS perf
  )
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY LABELS cft
  )
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY ENVIRONMENT
             "TSAN_OPTIONS=suppressions=${CCF_DIR}/tsan_env_suppressions"
  )
endfunction()

# Picobench wrapper
function(add_picobench name)
  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_include_directories(${name} PRIVATE src ${PARSED_ARGS_INCLUDE_DIRS})

  target_link_libraries(
    ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${PARSED_ARGS_LINK_LIBS}
                    ccfcrypto.host
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

  set_property(
    TEST ${name}
    APPEND
    PROPERTY ENVIRONMENT
             "TSAN_OPTIONS=suppressions=${CCF_DIR}/tsan_env_suppressions"
  )
endfunction()
