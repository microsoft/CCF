// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/core/runtime.h"

#include "ccf/service/tables/jsengine.h"
#include "ccf/tx.h"
#include "js/global_class_ids.h"

#include <vector>

namespace ccf::js::core
{
  Runtime::Runtime()
  {
    rt = JS_NewRuntime();
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
      {kv_map_handle_class_id, &kv_map_handle_class_def},
      {node_class_id, &node_class_def},
      {network_class_id, &network_class_def},
      {rpc_class_id, &rpc_class_def},
      {host_class_id, &host_class_def},
      {consensus_class_id, &consensus_class_def},
      {historical_class_id, &historical_class_def},
      {historical_state_class_id, &historical_state_class_def}};
    for (auto [class_id, class_def] : classes)
    {
      auto ret = JS_NewClass(rt, class_id, class_def);
      if (ret != 0)
        throw std::logic_error(fmt::format(
          "Failed to register JS class definition {}", class_def->class_name));
    }
  }

  void Runtime::reset_runtime_options()
  {
    JS_SetMaxStackSize(rt, 0);
    JS_SetMemoryLimit(rt, -1);
    JS_SetInterruptHandler(rt, NULL, NULL);
  }

  void Runtime::set_runtime_options(kv::Tx* tx, RuntimeLimitsPolicy policy)
  {
    size_t stack_size = default_stack_size;
    size_t heap_size = default_heap_size;

    const auto jsengine = tx->ro<ccf::JSEngine>(ccf::Tables::JSENGINE);
    const std::optional<JSRuntimeOptions> js_runtime_options = jsengine->get();

    if (js_runtime_options.has_value())
    {
      bool no_lower_than_defaults =
        policy == RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS;

      heap_size = std::max(
        js_runtime_options.value().max_heap_bytes,
        no_lower_than_defaults ? default_heap_size : 0);
      stack_size = std::max(
        js_runtime_options.value().max_stack_bytes,
        no_lower_than_defaults ? default_stack_size : 0);
      max_exec_time = std::max(
        std::chrono::milliseconds{
          js_runtime_options.value().max_execution_time_ms},
        no_lower_than_defaults ? default_max_execution_time :
                                 std::chrono::milliseconds{0});
      log_exception_details = js_runtime_options.value().log_exception_details;
      return_exception_details =
        js_runtime_options.value().return_exception_details;
    }

    JS_SetMaxStackSize(rt, stack_size);
    JS_SetMemoryLimit(rt, heap_size);
  }
}
