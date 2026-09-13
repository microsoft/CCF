# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)

project(programmability LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

include(../common.cmake)

add_ccf_app(
  programmability
  SRCS programmability.cpp $<TARGET_OBJECTS:ccf_app_main>
)
