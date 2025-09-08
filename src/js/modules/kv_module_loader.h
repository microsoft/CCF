// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/js/modules/module_loader_interface.h"
#include "ccf/service/tables/modules.h"
#include "ccf/tx.h"
#include "ds/internal_logger.h.h"

#include <string>

namespace ccf::js::modules
{
  class KvModuleLoader : public ModuleLoaderInterface
  {
  protected:
    ccf::Modules::ReadOnlyHandle* modules_handle;

  public:
    KvModuleLoader(ccf::Modules::ReadOnlyHandle* mh) : modules_handle(mh) {}

    virtual std::optional<js::core::JSWrappedValue> get_module(
      std::string_view module_name, js::core::Context& ctx) override
    {
      std::string module_name_kv(module_name);
      if (module_name_kv[0] != '/')
      {
        module_name_kv.insert(0, "/");
      }

      CCF_APP_TRACE("Looking for module '{}' in KV", module_name_kv);

      auto module_str = modules_handle->get(module_name_kv);
      if (!module_str.has_value())
      {
        CCF_APP_TRACE("Module '{}' not found", module_name_kv);
        return std::nullopt;
      }

      auto module_name_quickjs = module_name_kv.c_str() + 1;
      const char* buf = module_str->c_str();
      size_t buf_len = module_str->size();
      auto parsed_module = ctx.eval(
        buf,
        buf_len,
        module_name_quickjs,
        JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
      if (parsed_module.is_exception())
      {
        auto [reason, trace] = ctx.error_message();

        auto& rt = ctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        throw std::runtime_error(fmt::format(
          "Failed to compile module '{}': {}", module_name, reason));
      }

      CCF_APP_TRACE(
        "Module '{}' found in KV (table: {})",
        module_name_kv,
        modules_handle->get_name_of_map());
      return parsed_module;
    }
  };
}
