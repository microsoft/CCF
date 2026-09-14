# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)
project(stacktrace_installed_consumer LANGUAGES CXX)
find_package(ccf CONFIG REQUIRED)

get_target_property(link_libraries ccf_tasks INTERFACE_LINK_LIBRARIES)
get_target_property(definitions ccf_tasks INTERFACE_COMPILE_DEFINITIONS)
if(definitions MATCHES "CCF_STACKTRACE_USE_STD")
  message(FATAL_ERROR "The backend definition must not leak to consumers")
endif()
if(EXPECT_BACKEND STREQUAL "STD" AND link_libraries MATCHES "(^|[;:])backtrace")
  message(FATAL_ERROR "STD consumers must not link standalone libbacktrace")
endif()
if(link_libraries MATCHES "/[^;>]*lib(stdc\\+\\+|backtrace)")
  message(
    FATAL_ERROR
    "Stacktrace support libraries must be exported by link name"
  )
endif()

add_executable(stacktrace_consumer main.cpp)
target_include_directories(
  stacktrace_consumer
  PRIVATE
    "${CCF_DIR}/include"
    "${CCF_DIR}/include/ccf/_private"
    "${CCF_DIR}/include/3rdparty"
)
# Deliberately no explicit support libraries: the installed target must supply them.
target_link_libraries(stacktrace_consumer PRIVATE ccf_tasks)
enable_testing()
add_test(NAME stacktrace_installed_consumer COMMAND stacktrace_consumer)
set_tests_properties(
  stacktrace_installed_consumer
  PROPERTIES PASS_REGULAR_EXPRESSION "Stack trace:"
)
