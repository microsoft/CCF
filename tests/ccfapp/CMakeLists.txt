# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Never include this from main CCF CMakeLists, it's meant to be a standalone
# CMake thing for testing against CCF packages.

cmake_minimum_required(VERSION 3.21)

project(ccfapp LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

add_ccf_app(ccfapp SRCS ccfapp.cpp)

include(cpack.cmake)

install(
  TARGETS ccfapp
  EXPORT ccfapp
  DESTINATION bin
)
