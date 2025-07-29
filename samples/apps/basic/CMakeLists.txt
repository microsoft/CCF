# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)

project(basic LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

add_ccf_app(basic SRCS basic.cpp ${CCF_DIR}/samples/apps/main.cpp)
