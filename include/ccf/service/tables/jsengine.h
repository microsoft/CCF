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

  // Manually implemented to_json and from_json, so that we are maximally
  // permissive in deserialisation (use defaults), but maximally verbose in
  // serialisation (describe all fields)
  inline void to_json(nlohmann::json& j, const JSRuntimeOptions& options)
  {
    j = nlohmann::json::object();
    j["max_heap_bytes"] = options.max_heap_bytes;
    j["max_stack_bytes"] = options.max_stack_bytes;
    j["max_execution_time_ms"] = options.max_execution_time_ms;
    j["log_exception_details"] = options.log_exception_details;
    j["return_exception_details"] = options.return_exception_details;
    j["max_cached_interpreters"] = options.max_cached_interpreters;
  }

  inline void from_json(const nlohmann::json& j, JSRuntimeOptions& options)
  {
    {
      const auto it = j.find("max_heap_bytes");
      if (it != j.end())
      {
        options.max_heap_bytes =
          it->get<decltype(JSRuntimeOptions::max_heap_bytes)>();
      }
    }

    {
      const auto it = j.find("max_stack_bytes");
      if (it != j.end())
      {
        options.max_stack_bytes =
          it->get<decltype(JSRuntimeOptions::max_stack_bytes)>();
      }
    }
    {
      const auto it = j.find("max_execution_time_ms");
      if (it != j.end())
      {
        options.max_execution_time_ms =
          it->get<decltype(JSRuntimeOptions::max_execution_time_ms)>();
      }
    }
    {
      const auto it = j.find("log_exception_details");
      if (it != j.end())
      {
        options.log_exception_details =
          it->get<decltype(JSRuntimeOptions::log_exception_details)>();
      }
    }
    {
      const auto it = j.find("return_exception_details");
      if (it != j.end())
      {
        options.return_exception_details =
          it->get<decltype(JSRuntimeOptions::return_exception_details)>();
      }
    }
    {
      const auto it = j.find("max_cached_interpreters");
      if (it != j.end())
      {
        options.max_cached_interpreters =
          it->get<decltype(JSRuntimeOptions::max_cached_interpreters)>();
      }
    }
  }

  inline std::string schema_name(const JSRuntimeOptions*)
  {
    return "JSRuntimeOptions";
  }

  inline void fill_json_schema(nlohmann::json& schema, const JSRuntimeOptions*)
  {
    // TODO
  }

  using JSEngine = ServiceValue<JSRuntimeOptions>;

  namespace Tables
  {
    static constexpr auto JSENGINE = "public:ccf.gov.js_runtime_options";
  }
}