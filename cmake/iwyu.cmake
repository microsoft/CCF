# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

option(INCLUDE_WHAT_YOU_USE "Run include-what-you-use on the codebase" OFF)

if(NOT INCLUDE_WHAT_YOU_USE)
  return()
endif()

find_program(IWYU_EXE NAMES "include-what-you-use" "iwyu")
if(NOT IWYU_EXE)
  message(FATAL_ERROR "include-what-you-use requested but not found")
endif()

# -w suppresses compiler warnings so CI logs focus on IWYU findings.
# --error=1 selects IWYU's standard non-zero failure code, so any suggestion
# fails the build and enforces direct includes.
set(IWYU_COMMAND "${IWYU_EXE}" "-w" "-Xiwyu" "--error=1")
list(
  APPEND IWYU_COMMAND
  "-Xiwyu"
  "--mapping_file=${CMAKE_CURRENT_LIST_DIR}/iwyu.imp"
)

set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE ${IWYU_COMMAND})
message(STATUS "Using include-what-you-use from: ${IWYU_EXE}")
