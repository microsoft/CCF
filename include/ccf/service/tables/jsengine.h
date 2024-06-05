// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"

namespace ccf
{
  struct JSRuntimeOptions
  {
    struct Defaults
    {
      static constexpr size_t max_heap_bytes = 100 * 1024 * 1024;
      static constexpr size_t max_stack_bytes = 1024 * 1024;
      static constexpr uint64_t max_execution_time_ms = 1000;
      static constexpr bool log_exception_details = false;
      static constexpr bool return_exception_details = false;
      static constexpr size_t max_cached_interpreters = 10;
    };

    /// @brief heap size for QuickJS runtime
    size_t max_heap_bytes = Defaults::max_heap_bytes;
    /// @brief stack size for QuickJS runtime
    size_t max_stack_bytes = Defaults::max_stack_bytes;
    /// @brief max execution time for QuickJS
    uint64_t max_execution_time_ms = Defaults::max_execution_time_ms;
    /// @brief emit exception details to the log
    /// NOTE: this is a security risk as it may leak sensitive information
    ///       to anyone with access to the application log, which is
    ///       unprotected.
    bool log_exception_details = Defaults::log_exception_details;
    /// @brief return exception details in the response
    /// NOTE: this is a security risk as it may leak sensitive information,
    ///       albeit to the caller only.
    bool return_exception_details = Defaults::return_exception_details;
    /// @brief how many interpreters may be cached in-memory for future reuse
    size_t max_cached_interpreters = Defaults::max_cached_interpreters;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JSRuntimeOptions)
  DECLARE_JSON_REQUIRED_FIELDS(
    JSRuntimeOptions, max_heap_bytes, max_stack_bytes, max_execution_time_ms)
  DECLARE_JSON_OPTIONAL_FIELDS(
    JSRuntimeOptions,
    log_exception_details,
    return_exception_details,
    max_cached_interpreters);

  using JSEngine = ServiceValue<JSRuntimeOptions>;

  namespace Tables
  {
    static constexpr auto JSENGINE = "public:ccf.gov.js_runtime_options";
  }
}