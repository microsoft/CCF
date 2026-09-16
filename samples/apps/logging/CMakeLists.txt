# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)

project(logging LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

add_ccf_app(
  logging_common
  OBJECT_LIBRARY
  SRCS logging.cpp create_tx_claims_digest.cpp
)

add_ccf_app(logging SRCS ../main.cpp LINK_LIBS logging_common)

add_ccf_app(
  logging_cose_only
  SRCS get_ledger_sign_mode_cose.cpp ../main.cpp
  LINK_LIBS logging_common
)

add_ccf_app(
  logging_cose_only_allow_join_dual
  SRCS get_ledger_sign_mode_cose_allow_join_dual.cpp ../main.cpp
  LINK_LIBS logging_common
)
