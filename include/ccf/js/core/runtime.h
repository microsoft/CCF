// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"

#include <chrono>
#include <quickjs/quickjs.h>

namespace ccf::js::core
{
  enum class RuntimeLimitsPolicy
  {
    NONE,
    NO_LOWER_THAN_DEFAULTS
  };

  class Runtime
  {
    JSRuntime* rt = nullptr;

    std::chrono::milliseconds max_exec_time = default_max_execution_time;

    void add_ccf_classdefs();

  public:
    static constexpr std::chrono::milliseconds default_max_execution_time{1000};
    static constexpr size_t default_stack_size = 1024 * 1024;
    static constexpr size_t default_heap_size = 100 * 1024 * 1024;

    bool log_exception_details = false;
    bool return_exception_details = false;

    Runtime();
    ~Runtime();

    operator JSRuntime*() const
    {
      return rt;
    }

    void reset_runtime_options();
    void set_runtime_options(kv::Tx* tx, RuntimeLimitsPolicy policy);

    std::chrono::milliseconds get_max_exec_time() const
    {
      return max_exec_time;
    }
  };
}
