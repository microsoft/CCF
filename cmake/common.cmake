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

  if(COVERAGE)
    set_property(
      TEST ${name}
      APPEND
      PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${name}-%p.profraw"
    )
  endif()

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

# Convert a CMake list to a JSON array of strings
function(_cmake_list_to_json_array LIST_VAR OUTPUT_VAR)
  set(JSON_STR "[")
  set(FIRST TRUE)
  foreach(ITEM IN LISTS LIST_VAR)
    if(FIRST)
      set(FIRST FALSE)
    else()
      string(APPEND JSON_STR ", ")
    endif()
    # Escape backslashes and quotes for JSON
    string(REPLACE "\\" "\\\\" ITEM "${ITEM}")
    string(REPLACE "\"" "\\\"" ITEM "${ITEM}")
    string(APPEND JSON_STR "\"${ITEM}\"")
  endforeach()
  string(APPEND JSON_STR "]")
  set(${OUTPUT_VAR}
      "${JSON_STR}"
      PARENT_SCOPE
  )
endfunction()

# Extract values from a flag-value list (e.g. --constitution /path1
# --constitution /path2) Returns only the values, filtering out the flag tokens.
function(_extract_flag_values FLAG_NAME INPUT_LIST OUTPUT_VAR)
  set(RESULT "")
  set(TAKE_NEXT FALSE)
  foreach(ITEM IN LISTS INPUT_LIST)
    if(TAKE_NEXT)
      list(APPEND RESULT "${ITEM}")
      set(TAKE_NEXT FALSE)
    elseif("${ITEM}" STREQUAL "${FLAG_NAME}")
      set(TAKE_NEXT TRUE)
    endif()
  endforeach()
  set(${OUTPUT_VAR}
      "${RESULT}"
      PARENT_SCOPE
  )
endfunction()

# Write a shared e2e_config.json that the Python test framework reads via
# --defaults-file to populate CLI argument defaults (constitution, binary_dir,
# log_level, etc).  This removes the need to pass common flags when invoking
# tests manually.
function(write_e2e_config)
  cmake_parse_arguments(
    PARSE_ARGV 0 CFG "" "LOG_LEVEL;WORKER_THREADS;TICK_MS" "CONSTITUTION"
  )

  # constitution is passed as --constitution /a --constitution /b … Extract just
  # the paths.
  _extract_flag_values(
    "--constitution" "${CFG_CONSTITUTION}" CONSTITUTION_PATHS
  )
  _cmake_list_to_json_array("${CONSTITUTION_PATHS}" CONSTITUTION_JSON)

  set(JSON_CONTENT "{\n")
  string(APPEND JSON_CONTENT "  \"binary_dir\": \"${CMAKE_BINARY_DIR}\",\n")
  string(APPEND JSON_CONTENT "  \"library_dir\": \"${CMAKE_BINARY_DIR}\",\n")
  string(APPEND JSON_CONTENT "  \"constitution\": ${CONSTITUTION_JSON},\n")
  string(APPEND JSON_CONTENT "  \"log_level\": \"${CFG_LOG_LEVEL}\",\n")
  string(APPEND JSON_CONTENT "  \"worker_threads\": ${CFG_WORKER_THREADS},\n")
  string(APPEND JSON_CONTENT "  \"tick_ms\": ${CFG_TICK_MS}\n")
  string(APPEND JSON_CONTENT "}\n")

  file(WRITE "${CMAKE_BINARY_DIR}/e2e_config.json" "${JSON_CONTENT}")
endfunction()

# Accumulate a test entry into the global e2e test config. Call
# write_e2e_test_configs() after all tests are defined.
function(_accumulate_e2e_test_config)
  cmake_parse_arguments(
    PARSE_ARGV 0 CFG "" "NAME;PYTHON_SCRIPT;LABEL"
    "CONSTITUTION;ADDITIONAL_ARGS"
  )

  # Extract constitution file paths (strip --constitution flags)
  _extract_flag_values(
    "--constitution" "${CFG_CONSTITUTION}" CONSTITUTION_PATHS
  )
  _cmake_list_to_json_array("${CONSTITUTION_PATHS}" CONSTITUTION_JSON)

  # Additional args as flat array
  _cmake_list_to_json_array("${CFG_ADDITIONAL_ARGS}" ADDITIONAL_ARGS_JSON)

  set(LABEL_VALUE "${CFG_LABEL}")
  if(NOT LABEL_VALUE)
    set(LABEL_VALUE "")
  endif()

  # Escape the python script path
  string(REPLACE "\\" "\\\\" SCRIPT "${CFG_PYTHON_SCRIPT}")
  string(REPLACE "\"" "\\\"" SCRIPT "${SCRIPT}")

  set(ENTRY
      "    \"${CFG_NAME}\": {\n\
      \"python_script\": \"${SCRIPT}\",\n\
      \"label\": \"${LABEL_VALUE}\",\n\
      \"constitution\": ${CONSTITUTION_JSON},\n\
      \"additional_args\": ${ADDITIONAL_ARGS_JSON}\n\
    }"
  )

  set_property(GLOBAL APPEND PROPERTY _E2E_TEST_CONFIG_ENTRIES "${ENTRY}")
endfunction()

# Write the consolidated e2e_tests.json to the build directory. Must be called
# after all add_e2e_test() invocations.
function(write_e2e_test_configs)
  get_property(ENTRIES GLOBAL PROPERTY _E2E_TEST_CONFIG_ENTRIES)

  set(JSON_CONTENT "{\n")
  list(LENGTH ENTRIES NUM_ENTRIES)
  math(EXPR LAST_INDEX "${NUM_ENTRIES} - 1")
  set(INDEX 0)
  foreach(ENTRY IN LISTS ENTRIES)
    string(APPEND JSON_CONTENT "${ENTRY}")
    if(INDEX LESS LAST_INDEX)
      string(APPEND JSON_CONTENT ",")
    endif()
    string(APPEND JSON_CONTENT "\n")
    math(EXPR INDEX "${INDEX} + 1")
  endforeach()
  string(APPEND JSON_CONTENT "}\n")

  file(WRITE "${CMAKE_BINARY_DIR}/e2e_tests.json" "${JSON_CONTENT}")
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

    # Build the full argument list for the test (everything after the python
    # script)
    set(FULL_TEST_ARGS
        -b
        .
        --label
        ${PARSED_ARGS_NAME}
        ${CCF_NETWORK_TEST_ARGS}
        ${PARSED_ARGS_CONSTITUTION}
        ${PARSED_ARGS_ADDITIONAL_ARGS}
        --tick-ms
        ${NODE_TICK_MS}
    )

    add_test(
      NAME ${PARSED_ARGS_NAME}
      COMMAND ${PYTHON_WRAPPER} ${PARSED_ARGS_PYTHON_SCRIPT} ${FULL_TEST_ARGS}
      CONFIGURATIONS ${PARSED_ARGS_CONFIGURATIONS}
    )

    # Make python test client framework importable
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH}"
    )

    set(TEST_ENV_VARS "PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH}")

    if(SHUFFLE_SUITE)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "SHUFFLE_SUITE=1"
      )
      list(APPEND TEST_ENV_VARS "SHUFFLE_SUITE=1")
    endif()

    if("${PARSED_ARGS_LABEL}" STREQUAL "partitions")
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1"
      )
      list(APPEND TEST_ENV_VARS "PYTHONDONTWRITEBYTECODE=1")
    endif()

    add_san_test_properties(${PARSED_ARGS_NAME})

    if(COVERAGE)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY
          ENVIRONMENT
          "LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/${PARSED_ARGS_NAME}-%p.profraw"
      )
    endif()

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
      list(APPEND TEST_ENV_VARS "CURL_CLIENT=ON")
    endif()

    # Accumulate JSON configuration for the test
    _accumulate_e2e_test_config(
      NAME
      "${PARSED_ARGS_NAME}"
      PYTHON_SCRIPT
      "${PARSED_ARGS_PYTHON_SCRIPT}"
      LABEL
      "${PARSED_ARGS_LABEL}"
      CONSTITUTION
      ${PARSED_ARGS_CONSTITUTION}
      ADDITIONAL_ARGS
      ${PARSED_ARGS_ADDITIONAL_ARGS}
    )
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
      "$<TARGET_FILE:${name}> --samples=10 --out-fmt=csv --output=${name}.csv && cat ${name}.csv"
  )
  set_property(
    TEST ${name}
    APPEND
    PROPERTY LABELS benchmark
  )

  add_san_test_properties(${name})
endfunction()
