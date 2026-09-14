# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)
project(stacktrace_detection_fixture LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(BUILD_FIXTURE_LIBRARIES)
  foreach(library IN ITEMS default stdc++exp stdc++_libbacktrace backtrace)
    string(MAKE_C_IDENTIFIER "${library}" target)
    add_library(${target} STATIC support.cpp)
    set_target_properties(
      ${target}
      PROPERTIES
        OUTPUT_NAME "${library}"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${library}"
    )
  endforeach()
  add_library(unusable STATIC unusable.cpp)
  return()
endif()

# No system libbacktrace installation may satisfy a missing-fixture test.
set(CMAKE_FIND_ROOT_PATH "${CMAKE_BINARY_DIR}/empty-root")
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
if(NOT FIXTURE_FALLBACK STREQUAL "missing")
  if(NOT FIXTURE_FALLBACK STREQUAL "missing-header")
    set(BACKTRACE_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  endif()
  if(FIXTURE_FALLBACK STREQUAL "unusable")
    set(BACKTRACE_LIBRARY "${FIXTURE_LIBRARY_DIR}/libunusable.a")
  elseif(NOT FIXTURE_FALLBACK STREQUAL "missing-library")
    set(BACKTRACE_LIBRARY "${FIXTURE_LIBRARY_DIR}/backtrace/libbacktrace.a")
  endif()
endif()

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_REQUIRED_FLAGS "-DCCF_STACKTRACE_FIXTURE_FLAG=1")
set(CMAKE_REQUIRED_DEFINITIONS "-DCCF_STACKTRACE_FIXTURE_DEFINITION=1")
set(CMAKE_REQUIRED_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(CMAKE_REQUIRED_LINK_OPTIONS "-L${FIXTURE_LIBRARY_DIR}/${FIXTURE_SUPPORT}")
set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_DL_LIBS}")
set(CMAKE_REQUIRED_QUIET ON)
if(FIXTURE_SUPPORT STREQUAL "default")
  list(APPEND CMAKE_REQUIRED_LIBRARIES default)
endif()
if(FIXTURE_STD_FAILURE)
  list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D${FIXTURE_STD_FAILURE}=1")
endif()

set(
  preserved
  CMAKE_TRY_COMPILE_TARGET_TYPE
  CMAKE_CXX_STANDARD
  CMAKE_CXX_STANDARD_REQUIRED
  CMAKE_CXX_FLAGS
  CMAKE_REQUIRED_FLAGS
  CMAKE_REQUIRED_DEFINITIONS
  CMAKE_REQUIRED_INCLUDES
  CMAKE_REQUIRED_LINK_OPTIONS
  CMAKE_REQUIRED_LIBRARIES
  CMAKE_REQUIRED_QUIET
  CMAKE_REQUIRED_LINK_DIRECTORIES
)
foreach(variable IN LISTS preserved)
  if(DEFINED ${variable})
    set("saved_${variable}" "${${variable}}")
  endif()
endforeach()

include("${CCF_SOURCE_DIR}/cmake/stacktrace.cmake")

foreach(variable IN LISTS preserved)
  if(DEFINED saved_${variable})
    if(NOT "${${variable}}" STREQUAL "${saved_${variable}}")
      message(FATAL_ERROR "Detection changed ${variable}")
    endif()
  elseif(DEFINED ${variable})
    message(FATAL_ERROR "Detection defined previously unset ${variable}")
  endif()
endforeach()
if(NOT CCF_STACKTRACE_BACKEND_RESOLVED STREQUAL EXPECT_BACKEND)
  message(
    FATAL_ERROR
    "Expected ${EXPECT_BACKEND}, got ${CCF_STACKTRACE_BACKEND_RESOLVED}"
  )
endif()
if(NOT CCF_STACKTRACE_SUPPORT_LIBRARY STREQUAL EXPECT_SUPPORT)
  message(
    FATAL_ERROR
    "Expected support '${EXPECT_SUPPORT}', got '${CCF_STACKTRACE_SUPPORT_LIBRARY}'"
  )
endif()
if(EXPECT_BACKEND STREQUAL "STD" AND FIXTURE_FALLBACK STREQUAL "missing")
  if(DEFINED BACKTRACE_INCLUDE_DIR OR DEFINED BACKTRACE_LIBRARY)
    message(FATAL_ERROR "STD selection discovered standalone libbacktrace")
  endif()
endif()
