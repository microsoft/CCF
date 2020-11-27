# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.13)

set(CCF_VERSION "0.15.2")
set(CCF_DIR "/opt/ccf-${CCF_VERSION}" CACHE PATH "Path to CCF install")
set(CCF_PYTHON_VERSION "${CCF_VERSION}" CACHE PATH "Version of CCF Python package to install (should match CCF version)")
include(${CCF_DIR}/cmake/preproject.cmake)

project(logging LANGUAGES C CXX)

#TODO: Should be obtained through FindPackage
include(${CCF_DIR}/cmake/ccf.cmake)
include(${CCF_DIR}/cmake/ccf_app.cmake)
include(${CCF_DIR}/cmake/tools.cmake)

include_directories(
  ${CCF_DIR}/include/ccf
  ${CCF_DIR}/include/3rdparty
  ${CCF_DIR}/generated
  ${CCF_DIR}/include/3rdparty/msgpack-c
  ${CCF_DIR}/include/3rdparty/flatbuffers/include
)

add_ccf_app(
  logging SRCS logging.cpp
)

# Generate an ephemeral signing key
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
  COMMAND openssl genrsa -out ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem -3 3072
)
add_custom_target(
  signing_key ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

sign_app_library(
  logging.enclave ${CMAKE_CURRENT_SOURCE_DIR}/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)