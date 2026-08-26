# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)

project(basic_rust LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

add_ccf_rust_app(
  basic_rust
  MANIFEST_PATH ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml
  PACKAGE ccf-basic-rust
)
