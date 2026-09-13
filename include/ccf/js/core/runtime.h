// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/jsengine.h"

#include <chrono>
#include <optional>
#include <quickjs/quickjs.h>

namespace ccf::js::core
{
  enum class RuntimeLimitsPolicy : uint8_t
  {
    NONE,
    NO_LOWER_THAN_DEFAULTS
  };

  class Runtime
  {
    JSRuntime* rt = nullptr;

    std::chrono::milliseconds max_exec_time{
      ccf::JSRuntimeOptions::Defaults::max_execution_time_ms};

    // The options and policy most recently applied by set_runtime_options, so
    // that nested runtimes created during execution can be bounded by the same
    // limits. Cleared by reset_runtime_options.
    std::optional<ccf::JSRuntimeOptions> current_options = std::nullopt;
    RuntimeLimitsPolicy current_policy = RuntimeLimitsPolicy::NONE;

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

    [[nodiscard]] const std::optional<ccf::JSRuntimeOptions>&
    get_current_options() const
    {
      return current_options;
    }

    [[nodiscard]] RuntimeLimitsPolicy get_current_policy() const
    {
      return current_policy;
    }
  };
}
