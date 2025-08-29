// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/openapi.h"
#include "ccf/service/map.h"

namespace ccf
{
  struct JSRuntimeOptions
  {
    struct Defaults
    {
      static constexpr size_t max_heap_bytes = 100 * 1024 * 1024;
      static constexpr size_t max_stack_bytes = 1024 * 1024;
      static constexpr uint64_t max_execution_time_ms = 5000;
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

#define FOREACH_JSENGINE_FIELD(XX) \
  XX(max_heap_bytes, decltype(JSRuntimeOptions::max_heap_bytes)) \
  XX(max_stack_bytes, decltype(JSRuntimeOptions::max_stack_bytes)) \
  XX(max_execution_time_ms, decltype(JSRuntimeOptions::max_execution_time_ms)) \
  XX(log_exception_details, decltype(JSRuntimeOptions::log_exception_details)) \
  XX( \
    return_exception_details, \
    decltype(JSRuntimeOptions::return_exception_details)) \
  XX( \
    max_cached_interpreters, \
    decltype(JSRuntimeOptions::max_cached_interpreters))

  // Manually implemented to_json and from_json, so that we are maximally
  // permissive in deserialisation (use defaults), but maximally verbose in
  // serialisation (describe all fields)
  inline void to_json(nlohmann::json& j, const JSRuntimeOptions& options)
  {
    j = nlohmann::json::object();
#define XX(field, field_type) j[#field] = options.field;

    FOREACH_JSENGINE_FIELD(XX)
#undef XX
  }

  inline void from_json(const nlohmann::json& j, JSRuntimeOptions& options)
  {
#define XX(field, field_type) \
  { \
    const auto it = j.find(#field); \
    if (it != j.end()) \
    { \
      options.field = it->get<field_type>(); \
    } \
  }

    FOREACH_JSENGINE_FIELD(XX)
#undef XX
  }

  inline std::string schema_name(const JSRuntimeOptions*)
  {
    return "JSRuntimeOptions";
  }

  inline void fill_json_schema(nlohmann::json& schema, const JSRuntimeOptions*)
  {
    schema = nlohmann::json::object();
    schema["type"] = "object";

    auto properties = nlohmann::json::object();
    {
#define XX(field, field_type) \
  properties[#field] = ccf::ds::openapi::components_ref_object( \
    ccf::ds::json::schema_name<field_type>());

      FOREACH_JSENGINE_FIELD(XX)
#undef XX
    }

    schema["properties"] = properties;
  }

#undef FOREACH_JSENGINE_FIELD

  using JSEngine = ServiceValue<JSRuntimeOptions>;

  namespace Tables
  {
    static constexpr auto JSENGINE = "public:ccf.gov.js_runtime_options";
  }
}