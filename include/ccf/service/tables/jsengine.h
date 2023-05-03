// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

namespace ccf
{
  struct JSRuntimeOptions
  {
    /// @brief heap size for QuickJS runtime
    size_t max_heap_bytes;
    /// @brief stack size for QuickJS runtime
    size_t max_stack_bytes;
    /// @brief max execution time for QuickJS
    uint64_t max_execution_time_ms;
    /// @brief emit exception details to the log
    /// NOTE: this is a security risk as it may leak sensitive information
    ///       to anyone with access to the application log, which is unprotected.
    bool log_exception_details = false;
    /// @brief return exception details in the response
    /// NOTE: this is a security risk as it may leak sensitive information,
    ///       albeit to the caller only.
    bool return_exception_details = false;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JSRuntimeOptions)
  DECLARE_JSON_REQUIRED_FIELDS(
    JSRuntimeOptions, max_heap_bytes, max_stack_bytes, max_execution_time_ms)
  DECLARE_JSON_OPTIONAL_FIELDS(JSRuntimeOptions, log_exception_details, return_exception_details);

  using JSEngine = ServiceValue<JSRuntimeOptions>;

  namespace Tables
  {
    static constexpr auto JSENGINE = "public:ccf.gov.js_runtime_options";
  }
}