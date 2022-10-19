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
  };

  DECLARE_JSON_TYPE(JSRuntimeOptions)
  DECLARE_JSON_REQUIRED_FIELDS(
    JSRuntimeOptions, max_heap_bytes, max_stack_bytes)

  using JSEngine = ServiceValue<JSRuntimeOptions>;

  namespace Tables
  {
    static constexpr auto JSENGINE = "public:ccf.gov.js_runtime_options";
  }
}