# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(
  NOT
    CCF_DIAGNOSTIC_OUTPUT_NAME
      MATCHES
      "^basic_(queue_probe|poll_cached|read_ahead)$"
)
  message(FATAL_ERROR "Unexpected diagnostic output name")
endif()

cmake_language(
  DEFER
  CALL set_target_properties
  basic
  PROPERTIES
  OUTPUT_NAME
  "${CCF_DIAGNOSTIC_OUTPUT_NAME}"
)
