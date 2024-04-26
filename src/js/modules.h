// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/modules.h"

#include <quickjs/quickjs.h>

namespace ccf::js
{
  static inline JSWrappedValue load_app_module(
    JSContext* ctx, const char* module_name, kv::Tx* tx)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    std::string module_name_kv(module_name);
    if (module_name_kv[0] != '/')
    {
      module_name_kv.insert(0, "/");
    }
    // conforms to quickjs' default module filename normalizer
    auto module_name_quickjs = module_name_kv.c_str() + 1;

    auto loaded_module = jsctx.get_module_from_cache(module_name_quickjs);
    if (loaded_module.has_value())
    {
      LOG_TRACE_FMT("Using module from interpreter cache '{}'", module_name_kv);
      return loaded_module.value();
    }

    const auto modules = tx->ro<ccf::Modules>(ccf::Tables::MODULES);

    std::optional<std::vector<uint8_t>> bytecode;
    const auto modules_quickjs_bytecode = tx->ro<ccf::ModulesQuickJsBytecode>(
      ccf::Tables::MODULES_QUICKJS_BYTECODE);
    bytecode = modules_quickjs_bytecode->get(module_name_kv);
    if (bytecode)
    {
      auto modules_quickjs_version = tx->ro<ccf::ModulesQuickJsVersion>(
        ccf::Tables::MODULES_QUICKJS_VERSION);
      if (modules_quickjs_version->get() != std::string(ccf::quickjs_version))
        bytecode = std::nullopt;
    }

    JSWrappedValue module_val;

    if (!bytecode)
    {
      LOG_TRACE_FMT("Loading module '{}'", module_name_kv);

      auto module = modules->get(module_name_kv);
      auto& js = module.value();

      const char* buf = js.c_str();
      size_t buf_len = js.size();
      module_val = jsctx.eval(
        buf,
        buf_len,
        module_name_quickjs,
        JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
      if (module_val.is_exception())
      {
        auto [reason, trace] = jsctx.error_message();

        auto& rt = jsctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        throw std::runtime_error(fmt::format(
          "Failed to compile module '{}': {}", module_name, reason));
      }
    }
    else
    {
      LOG_TRACE_FMT("Loading module from bytecode cache '{}'", module_name_kv);

      module_val = jsctx.read_object(
        bytecode->data(), bytecode->size(), JS_READ_OBJ_BYTECODE);
      if (module_val.is_exception())
      {
        auto [reason, trace] = jsctx.error_message();

        auto& rt = jsctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        throw std::runtime_error(fmt::format(
          "Failed to deserialize bytecode for module '{}': {}",
          module_name,
          reason));
      }
      if (JS_ResolveModule(ctx, module_val.val) < 0)
      {
        auto [reason, trace] = jsctx.error_message();

        auto& rt = jsctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        throw std::runtime_error(fmt::format(
          "Failed to resolve dependencies for module '{}': {}",
          module_name,
          reason));
      }
    }

    LOG_TRACE_FMT("Adding module to interpreter cache '{}'", module_name_kv);
    jsctx.load_module_to_cache(module_name_quickjs, module_val);

    return module_val;
  }

  static inline JSModuleDef* js_app_module_loader(
    JSContext* ctx, const char* module_name, void* opaque)
  {
    auto tx = (kv::Tx*)opaque;

    try
    {
      auto module_val = load_app_module(ctx, module_name, tx);
      return (JSModuleDef*)JS_VALUE_GET_PTR(module_val.val);
    }
    catch (const std::exception& exc)
    {
      JS_ThrowReferenceError(ctx, "%s", exc.what());
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
      auto [reason, trace] = jsctx.error_message();

      auto& rt = jsctx.runtime();
      if (rt.log_exception_details)
      {
        CCF_APP_FAIL(
          "Failed to load module '{}': {} {}",
          module_name,
          reason,
          trace.value_or("<no trace>"));
      }
      return nullptr;
    }
  }
}
