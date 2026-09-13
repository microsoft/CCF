# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(NOT TARGET ccf_app_main)
  add_ccf_app(ccf_app_main OBJECT SRCS ${CMAKE_CURRENT_LIST_DIR}/main.cpp)
endif()
