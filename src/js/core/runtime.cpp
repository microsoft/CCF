// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/core/runtime.h"

#include "js/global_class_ids.h"

#include <vector>

namespace ccf::js::core
{
  Runtime::Runtime() : rt(JS_NewRuntime())
  {
    if (rt == nullptr)
    {
      throw std::runtime_error("Failed to initialise QuickJS runtime");
    }

    JS_SetRuntimeOpaque(rt, this);

    add_ccf_classdefs();
  }

  Runtime::~Runtime()
  {
    JS_FreeRuntime(rt);
  }

  void Runtime::add_ccf_classdefs()
  {
    std::vector<std::pair<JSClassID, JSClassDef*>> classes{
      {kv_class_id, &kv_class_def},
      {kv_historical_class_id, &kv_historical_class_def},
      {kv_map_handle_class_id, &kv_map_handle_class_def}};
    for (auto [class_id, class_def] : classes)
    {
      auto ret = JS_NewClass(rt, class_id, class_def);
      if (ret != 0)
      {
        throw std::logic_error(fmt::format(
          "Failed to register JS class definition {}", class_def->class_name));
      }
    }
  }

  void Runtime::reset_runtime_options()
  {
    using Defaults = ccf::JSRuntimeOptions::Defaults;

    JS_SetMemoryLimit(rt, -1);
    JS_SetMaxStackSize(rt, 0);

    this->max_exec_time =
      std::chrono::milliseconds{Defaults::max_execution_time_ms};
  }

  void Runtime::set_runtime_options(
    const std::optional<ccf::JSRuntimeOptions>& options_opt,
    RuntimeLimitsPolicy policy)
  {
    using Defaults = ccf::JSRuntimeOptions::Defaults;

    ccf::JSRuntimeOptions js_runtime_options =
      options_opt.value_or(ccf::JSRuntimeOptions{});

    bool no_lower_than_defaults =
      policy == RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS;

    auto heap_size = std::max(
      js_runtime_options.max_heap_bytes,
      no_lower_than_defaults ? Defaults::max_heap_bytes : 0);
    JS_SetMemoryLimit(rt, heap_size);

    auto stack_size = std::max(
      js_runtime_options.max_stack_bytes,
      no_lower_than_defaults ? Defaults::max_stack_bytes : 0);
    JS_SetMaxStackSize(rt, stack_size);

    this->max_exec_time = std::chrono::milliseconds{std::max(
      js_runtime_options.max_execution_time_ms,
      no_lower_than_defaults ? Defaults::max_execution_time_ms : 0)};

    this->log_exception_details = js_runtime_options.log_exception_details;
    this->return_exception_details =
      js_runtime_options.return_exception_details;
  }
}
