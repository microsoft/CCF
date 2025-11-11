// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/jsengine.h"

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

    std::chrono::milliseconds max_exec_time{
      ccf::JSRuntimeOptions::Defaults::max_execution_time_ms};

    void add_ccf_classdefs();

  public:
    bool log_exception_details =
      ccf::JSRuntimeOptions::Defaults::log_exception_details;
    bool return_exception_details =
      ccf::JSRuntimeOptions::Defaults::return_exception_details;

    Runtime();
    ~Runtime();

    operator JSRuntime*() const
    {
      return rt;
    }

    void reset_runtime_options();
    void set_runtime_options(
      const std::optional<ccf::JSRuntimeOptions>& options_opt,
      RuntimeLimitsPolicy policy);

    [[nodiscard]] std::chrono::milliseconds get_max_exec_time() const
    {
      return max_exec_time;
    }
  };
}
