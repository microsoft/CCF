# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)
if(NOT CCF_SOURCE_DIR OR NOT TEST_BINARY_DIR)
  message(FATAL_ERROR "CCF_SOURCE_DIR and TEST_BINARY_DIR are required")
endif()
set(fixture "${CCF_SOURCE_DIR}/tests/cmake/stacktrace_detection")
set(libraries "${TEST_BINARY_DIR}/libraries")

function(run_checked)
  execute_process(
    COMMAND ${ARGV}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
  )
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${ARGV}\n${output}\n${error}")
  endif()
endfunction()

run_checked(
  "${CMAKE_COMMAND}"
  -S
  "${fixture}"
  -B
  "${libraries}"
  "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
  -DBUILD_FIXTURE_LIBRARIES=ON
)
run_checked("${CMAKE_COMMAND}" --build "${libraries}")

function(
  check_case
  name
  mode
  support
  fallback
  backend
  expected_support
  failure
)
  execute_process(
    COMMAND
      "${CMAKE_COMMAND}" -S "${fixture}" -B "${TEST_BINARY_DIR}/${name}"
      "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
      "-DCCF_SOURCE_DIR=${CCF_SOURCE_DIR}" "-DFIXTURE_LIBRARY_DIR=${libraries}"
      "-DCCF_STACKTRACE_BACKEND=${mode}" "-DFIXTURE_SUPPORT=${support}"
      "-DFIXTURE_FALLBACK=${fallback}" "-DEXPECT_BACKEND=${backend}"
      "-DEXPECT_SUPPORT=${expected_support}" ${ARGN}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
  )
  if(failure)
    if(result EQUAL 0 OR NOT "${output}\n${error}" MATCHES "${failure}")
      message(
        FATAL_ERROR
        "${name}: expected failure '${failure}'\n${output}\n${error}"
      )
    endif()
  elseif(NOT result EQUAL 0)
    message(FATAL_ERROR "${name} failed:\n${output}\n${error}")
  endif()
  message(STATUS "Passed stacktrace detection: ${name}")
endfunction()

check_case(auto-default AUTO default missing STD "" "")
check_case(auto-exp AUTO stdc++exp missing STD stdc++exp "")
check_case(
  auto-legacy
  AUTO
  stdc++_libbacktrace
  missing
  STD
  stdc++_libbacktrace
  ""
)
check_case(forced-std STD stdc++exp missing STD stdc++exp "")
check_case(
  forced-fallback
  LIBBACKTRACE
  default
  usable
  LIBBACKTRACE
  backtrace
  ""
)
check_case(auto-fallback AUTO none usable LIBBACKTRACE backtrace "")
check_case(
  no-header
  AUTO
  stdc++exp
  usable
  LIBBACKTRACE
  backtrace
  ""
  -DFIXTURE_STD_FAILURE=CCF_FIXTURE_NO_HEADER
)
check_case(
  no-feature
  AUTO
  stdc++exp
  usable
  LIBBACKTRACE
  backtrace
  ""
  -DFIXTURE_STD_FAILURE=CCF_FIXTURE_NO_FEATURE
)
check_case(
  no-native-handle
  AUTO
  stdc++exp
  usable
  LIBBACKTRACE
  backtrace
  ""
  -DFIXTURE_STD_FAILURE=CCF_FIXTURE_NO_NATIVE_HANDLE
)
check_case(invalid INVALID none missing "" "" "Invalid CCF_STACKTRACE_BACKEND")
check_case(std-unavailable STD none usable "" "" "requires usable C\\+\\+23")
check_case(all-unavailable AUTO none missing "" "" "was not found")
check_case(
  missing-fallback-header
  AUTO
  none
  missing-header
  ""
  ""
  "was not found"
)
check_case(
  missing-fallback-library
  AUTO
  none
  missing-library
  ""
  ""
  "was not found"
)
check_case(
  fallback-unavailable
  LIBBACKTRACE
  default
  missing
  ""
  ""
  "was not found"
)
check_case(
  fallback-unusable
  LIBBACKTRACE
  none
  unusable
  ""
  ""
  "compile-and-link probe failed"
)
# Reuse a configure cache to ensure changing modes does not retain stale results.
check_case(auto-exp LIBBACKTRACE default usable LIBBACKTRACE backtrace "")
