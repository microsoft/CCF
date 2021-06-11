# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

project(splitid LANGUAGES CXX)

cmake_minimum_required(VERSION 3.11)
set(CMAKE_CXX_STANDARD 17)

set(SPLITID_DIR ${CMAKE_CURRENT_SOURCE_DIR})

option(TESTS "enable tests" ON)
option(TRACE "enable debug traces" OFF)

add_library(splitid INTERFACE)
target_include_directories(splitid INTERFACE .)

if(TRACE)
  target_compile_definitions(splitid INTERFACE SPLITID_TRACE_ENABLED)
endif()

install(TARGETS splitid)

find_package(OpenSSL)
target_link_libraries(splitid INTERFACE crypto)

if(TESTS)
  enable_testing()

  function(add_unit_test NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE $<BUILD_INTERFACE:splitid>)

    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
      target_compile_options(
        ${NAME} PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
      )
      target_link_options(${NAME} PRIVATE -fsanitize=undefined,address)
    endif()

    add_test(${NAME} ${NAME})
  endfunction()

  add_subdirectory(test)
endif()