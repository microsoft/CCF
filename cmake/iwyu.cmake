# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

option(INCLUDE_WHAT_YOU_USE "Run include-what-you-use on the codebase" OFF)
set(
  IWYU_MAPPING_DIR
  ""
  CACHE PATH
  "Directory containing include-what-you-use mapping files"
)

if(NOT INCLUDE_WHAT_YOU_USE)
  return()
endif()

find_program(IWYU_EXE NAMES "include-what-you-use" "iwyu")
if(NOT IWYU_EXE)
  message(FATAL_ERROR "include-what-you-use requested but not found")
endif()

# -w suppresses compiler warnings so CI logs focus on IWYU findings.
# --error=1 makes any IWYU suggestion fail the build and enforce direct includes.
set(IWYU_COMMAND "${IWYU_EXE}" "-w" "-Xiwyu" "--error=1")
get_filename_component(IWYU_BIN_DIR "${IWYU_EXE}" DIRECTORY)
set(
  IWYU_MAPPING_DIRS
  "${IWYU_MAPPING_DIR}"
  "${IWYU_BIN_DIR}/../share/include-what-you-use"
  "/usr/local/share/include-what-you-use"
  "/usr/share/include-what-you-use"
)
foreach(IWYU_MAPPING_CANDIDATE_DIR ${IWYU_MAPPING_DIRS})
  if(EXISTS "${IWYU_MAPPING_CANDIDATE_DIR}/libcxx.imp")
    list(
      APPEND IWYU_COMMAND
      "-Xiwyu"
      "--mapping_file=${IWYU_MAPPING_CANDIDATE_DIR}/libcxx.imp"
    )
    break()
  endif()
endforeach()

set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE ${IWYU_COMMAND})
message(STATUS "Using include-what-you-use from: ${IWYU_EXE}")
