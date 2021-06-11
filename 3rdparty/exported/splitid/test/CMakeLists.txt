# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

function(add_splitid_test target source)
  add_unit_test(${SPLITID_TEST_PREFIX}${target} ${source})
  set_tests_properties(
    ${SPLITID_TEST_PREFIX}${target} PROPERTIES LABELS "splitid"
  )
  target_include_directories(
      ${SPLITID_TEST_PREFIX}${target} PRIVATE ${SPLITID_DIR} ${DOCTEST_DIR} ${FMT_DIR}
  )
  if (WIN32)
    target_compile_definitions(${SPLITID_TEST_PREFIX}${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()
endfunction()

set(DOCTEST_DIR ${SPLITID_DIR}/../../test)
find_path(DOCTEST_DIR doctest.h REQUIRED PATHS ${DOCTEST_DIR})

set(FMT_DIR ${SPLITID_DIR}/..)
find_path(FMT_DIR format.h REQUIRED PATHS ${FMT_DIR})

add_splitid_test(unit_tests splitid.cpp)
