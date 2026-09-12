# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)

project(logging LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

include(../common.cmake)

add_ccf_app(logging_common OBJECT SRCS logging.cpp create_tx_claims_digest.cpp)

set(
  LOGGING_COMMON_OBJECTS
  $<TARGET_OBJECTS:logging_common>
  $<TARGET_OBJECTS:ccf_app_main>
)

add_ccf_app(logging SRCS ${LOGGING_COMMON_OBJECTS})

add_ccf_app(
  logging_cose_only
  SRCS ${LOGGING_COMMON_OBJECTS} get_ledger_sign_mode_cose.cpp
)

add_ccf_app(
  logging_cose_only_allow_join_dual
  SRCS ${LOGGING_COMMON_OBJECTS} get_ledger_sign_mode_cose_allow_join_dual.cpp
)
