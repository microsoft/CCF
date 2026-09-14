# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)
load_cache(
  "${CCF_BINARY_DIR}"
  READ_WITH_PREFIX build_
  CCF_STACKTRACE_BACKEND
  CCF_STACKTRACE_BACKEND_RESOLVED
  CCF_STACKTRACE_SUPPORT_LIBRARY
)
if(NOT build_CCF_STACKTRACE_BACKEND STREQUAL "AUTO")
  message(FATAL_ERROR "The normal AL4 build must exercise AUTO selection")
endif()
if(NOT build_CCF_STACKTRACE_BACKEND_RESOLVED STREQUAL "STD")
  message(FATAL_ERROR "AL4 AUTO selection must resolve to STD")
endif()
include("${CCF_BINARY_DIR}/CPackConfig.cmake")
if(CPACK_RPM_PACKAGE_REQUIRES MATCHES "libbacktrace")
  message(FATAL_ERROR "STD packages must not depend on standalone libbacktrace")
endif()
if(
  build_CCF_STACKTRACE_SUPPORT_LIBRARY MATCHES "^stdc\\+\\+"
  AND NOT CPACK_RPM_PACKAGE_REQUIRES MATCHES "libstdc\\+\\+-devel"
)
  message(
    FATAL_ERROR
    "The standard-library support archive needs libstdc++-devel"
  )
endif()
message(STATUS "AL4 AUTO selected STD; package dependencies match")
