// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"
#include "ccf/js/common_context.h"
#include "ccf/js/core/context.h"
#include "ccf/js/core/runtime.h"
#include "ccf/js/extensions/ccf/consensus.h"
#include "js/global_class_ids.h"
#include "js/interpreter_cache.h"

#include <quickjs/quickjs.h>

#define PICOBENCH_IMPLEMENT
#include <picobench/picobench.hpp>

namespace
{
  // These benchmarks exercise in-process interpreter primitives directly.
  // They do not include endpoint lookup, KV transactions, request-object
  // construction, authentication, or transport work.

  template <typename T>
  inline void do_not_optimize(const T& value)
  {
    asm volatile("" : : "r,m"(value) : "memory");
  }

  inline void clobber_memory()
  {
    asm volatile("" : : : "memory");
  }

  void create_quickjs_runtime(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      auto* runtime = JS_NewRuntime();
      if (runtime == nullptr)
      {
        throw std::runtime_error("Failed to create QuickJS runtime");
      }
      do_not_optimize(runtime);
      JS_FreeRuntime(runtime);
      clobber_memory();
    }
  }

  // Includes runtime creation and destruction around the minimal QuickJS
  // context, which installs only QuickJS's basic objects.
  void create_quickjs_raw_context(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      auto* runtime = JS_NewRuntime();
      if (runtime == nullptr)
      {
        throw std::runtime_error("Failed to create QuickJS runtime");
      }
      auto* context = JS_NewContextRaw(runtime);
      if (context == nullptr)
      {
        JS_FreeRuntime(runtime);
        throw std::runtime_error("Failed to create raw QuickJS context");
      }
      do_not_optimize(context);
      JS_FreeContext(context);
      JS_FreeRuntime(runtime);
      clobber_memory();
    }
  }

  // Includes the complete standard intrinsic set installed by JS_NewContext.
  void create_quickjs_standard_context(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      auto* runtime = JS_NewRuntime();
      if (runtime == nullptr)
      {
        throw std::runtime_error("Failed to create QuickJS runtime");
      }
      auto* context = JS_NewContext(runtime);
      if (context == nullptr)
      {
        JS_FreeRuntime(runtime);
        throw std::runtime_error("Failed to create standard QuickJS context");
      }
      do_not_optimize(context);
      JS_FreeContext(context);
      JS_FreeRuntime(runtime);
      clobber_memory();
    }
  }

  // Diagnostic only: contexts have fresh globals, but share runtime-owned
  // atoms, heap state, limits, and garbage collection across iterations.
  void create_quickjs_standard_context_on_existing_runtime(
    picobench::state& state)
  {
    auto* runtime = JS_NewRuntime();
    if (runtime == nullptr)
    {
      throw std::runtime_error("Failed to create QuickJS runtime");
    }

    for (auto _ : state)
    {
      (void)_;
      auto* context = JS_NewContext(runtime);
      if (context == nullptr)
      {
        JS_FreeRuntime(runtime);
        throw std::runtime_error("Failed to create standard QuickJS context");
      }
      do_not_optimize(context);
      JS_FreeContext(context);
      clobber_memory();
    }

    JS_FreeRuntime(runtime);
  }

  // Adds CCF runtime class definitions to bare QuickJS runtime lifecycle.
  void create_ccf_runtime(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      ccf::js::core::Runtime runtime;
      do_not_optimize(static_cast<JSRuntime*>(runtime));
      clobber_memory();
    }
  }

  // Adds the CCF Context wrapper and module-loader callback.
  void create_ccf_context(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      ccf::js::core::Context context(ccf::js::TxAccess::APP_RW);
      do_not_optimize(static_cast<JSContext*>(context));
      clobber_memory();
    }
  }

  // Adds the request-independent extensions installed by CommonContext.
  void create_ccf_common_context(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      ccf::js::CommonContext context(ccf::js::TxAccess::APP_RW);
      do_not_optimize(static_cast<JSContext*>(context));
      clobber_memory();
    }
  }

  // Matches the interpreter factory registered by
  // BaseDynamicJSEndpointRegistry, including its ConsensusExtension but
  // excluding registry and request work.
  void construct_interpreter_via_cache_factory(picobench::state& state)
  {
    ccf::js::InterpreterCache cache(1);
    cache.set_interpreter_factory([](ccf::js::TxAccess access) {
      auto context = std::make_shared<ccf::js::CommonContext>(access);
      context->add_extension(
        std::make_shared<ccf::js::extensions::ConsensusExtension>(nullptr));
      return context;
    });

    for (auto _ : state)
    {
      (void)_;
      auto context =
        cache.get_interpreter(ccf::js::TxAccess::APP_RW, std::nullopt, 0);
      do_not_optimize(context);
      clobber_memory();
    }
  }

  // Measures only the InterpreterCache LRU hit, shared_ptr return, and promote.
  void acquire_cached_interpreter_hit(picobench::state& state)
  {
    ccf::js::InterpreterCache cache(1);
    cache.set_interpreter_factory([](ccf::js::TxAccess access) {
      return std::make_shared<ccf::js::CommonContext>(access);
    });
    const auto reuse = ccf::endpoints::InterpreterReusePolicy{
      .kind = ccf::endpoints::InterpreterReusePolicy::Kind::KeyBased,
      .key = "benchmark"};
    auto initial = cache.get_interpreter(ccf::js::TxAccess::APP_RW, reuse, 0);

    for (auto _ : state)
    {
      (void)_;
      auto context = cache.get_interpreter(ccf::js::TxAccess::APP_RW, reuse, 0);
      if (context != initial)
      {
        throw std::runtime_error("Interpreter cache did not return a hit");
      }
      do_not_optimize(context);
      clobber_memory();
    }
  }

  constexpr auto ccf_module =
    "export function handler() { return ccf.strToBuf('value').byteLength; }";

  ccf::js::core::JSWrappedValue get_handler(
    ccf::js::core::Context& context, const char* module)
  {
    JS_UpdateStackTop(context.runtime());
    return context.get_exported_function(module, "handler", "benchmark.js");
  }

  // Includes CommonContext construction, module compilation and module-scope
  // evaluation, but does not call the exported function.
  void create_compile_and_evaluate_module(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      ccf::js::CommonContext context(ccf::js::TxAccess::APP_RW);
      auto handler = get_handler(context, ccf_module);
      do_not_optimize(handler.val);
      clobber_memory();
    }
  }

  // Adds one direct function call using a common CCF converter.
  void create_compile_evaluate_and_call(picobench::state& state)
  {
    for (auto _ : state)
    {
      (void)_;
      ccf::js::CommonContext context(ccf::js::TxAccess::APP_RW);
      auto handler = get_handler(context, ccf_module);
      auto result = context.call_with_rt_options(
        handler, {}, std::nullopt, ccf::js::core::RuntimeLimitsPolicy::NONE);
      if (result.is_exception())
      {
        throw std::runtime_error("Fresh CCF JS invocation failed");
      }
      do_not_optimize(result.val);
      clobber_memory();
    }
  }

  // Diagnostic lower bound. Setup is outside the timed loop, so this retains
  // one context and measures only runtime-limit setup and direct calls.
  void call_warm_handler(picobench::state& state)
  {
    ccf::js::CommonContext context(ccf::js::TxAccess::APP_RW);
    auto handler = get_handler(context, ccf_module);

    for (auto _ : state)
    {
      (void)_;
      auto result = context.call_with_rt_options(
        handler, {}, std::nullopt, ccf::js::core::RuntimeLimitsPolicy::NONE);
      if (result.is_exception())
      {
        throw std::runtime_error("Warm CCF JS invocation failed");
      }
      do_not_optimize(result.val);
      clobber_memory();
    }
  }

  // The lifecycle dimension is referenced by tests/convert_pico_to_bencher.py.
  // Update its js_interpreter_bench.csv specifications if this changes.
  const std::vector<int> lifecycle_iteration_counts = {100};
  const std::vector<int> fast_iteration_counts = {100000};

  PICOBENCH_SUITE("QuickJS interpreter lifecycle");
  PICOBENCH(create_quickjs_runtime)
    .iterations(lifecycle_iteration_counts)
    .baseline();
  PICOBENCH(create_quickjs_raw_context).iterations(lifecycle_iteration_counts);
  PICOBENCH(create_quickjs_standard_context)
    .iterations(lifecycle_iteration_counts);
  PICOBENCH(create_quickjs_standard_context_on_existing_runtime)
    .iterations(lifecycle_iteration_counts);

  PICOBENCH_SUITE("CCF interpreter lifecycle");
  PICOBENCH(create_ccf_runtime)
    .iterations(lifecycle_iteration_counts)
    .baseline();
  PICOBENCH(create_ccf_context).iterations(lifecycle_iteration_counts);
  PICOBENCH(create_ccf_common_context).iterations(lifecycle_iteration_counts);
  PICOBENCH(construct_interpreter_via_cache_factory)
    .iterations(lifecycle_iteration_counts);
  PICOBENCH(acquire_cached_interpreter_hit).iterations(fast_iteration_counts);

  PICOBENCH_SUITE("CCF fresh invocation");
  PICOBENCH(create_compile_and_evaluate_module)
    .iterations(lifecycle_iteration_counts)
    .baseline();
  PICOBENCH(create_compile_evaluate_and_call)
    .iterations(lifecycle_iteration_counts);
  PICOBENCH(call_warm_handler).iterations(fast_iteration_counts);
}

int main(int argc, char** argv)
{
  ccf::js::register_class_ids();
  ccf::logger::config::level() = ccf::LoggerLevel::FATAL;

  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}
