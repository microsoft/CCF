# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)

project(logging LANGUAGES C CXX)

option(USE_UNSAFE_VERSION "Use build with unsafe logging levels" OFF)

set(CCF_PROJECT "ccf_${COMPILE_TARGET}")
if(USE_UNSAFE_VERSION)
  set(CCF_PROJECT "${CCF_PROJECT}_unsafe")
endif()

if(NOT TARGET ${CCF_PROJECT})
  find_package(${CCF_PROJECT} REQUIRED)
endif()

add_ccf_app(logging SRCS logging.cpp)

# Generate an ephemeral signing key
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
  COMMAND openssl genrsa -out ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem -3
          3072
)
add_custom_target(
  logging_signing_key ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

sign_app_library(
  logging.enclave ${CMAKE_CURRENT_SOURCE_DIR}/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)
