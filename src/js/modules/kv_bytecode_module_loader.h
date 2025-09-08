// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/modules/module_loader_interface.h"
#include "ccf/service/tables/modules.h"
#include "ccf/tx.h"
#include "ccf/version.h"
#include "ds/internal_logger.h.h"

#include <string>

namespace ccf::js::modules
{
  class KvBytecodeModuleLoader : public ModuleLoaderInterface
  {
  protected:
    ccf::ModulesQuickJsBytecode::ReadOnlyHandle* modules_bytecode_handle;

    bool version_ok;

  public:
    KvBytecodeModuleLoader(
      ccf::ModulesQuickJsBytecode::ReadOnlyHandle* mbh,
      ccf::ModulesQuickJsVersion::ReadOnlyHandle* modules_version_handle) :
      modules_bytecode_handle(mbh)
    {
      const auto version_in_kv = modules_version_handle->get();
      const auto version_in_binary = std::string(ccf::quickjs_version);
      if (version_in_kv != version_in_binary)
      {
        CCF_APP_INFO(
          "Ignoring bytecode table, which was written for QuickJS {} (this "
          "node is running QuickJS {})",
          version_in_kv,
          version_in_binary);
        version_ok = false;
      }
      else
      {
        version_ok = true;
      }
    }

    virtual std::optional<js::core::JSWrappedValue> get_module(
      std::string_view module_name, js::core::Context& ctx) override
    {
      if (!version_ok)
      {
        return std::nullopt;
      }

      std::string module_name_kv(module_name);
      if (module_name_kv[0] != '/')
      {
        module_name_kv.insert(0, "/");
      }

      CCF_APP_TRACE("Looking for module '{}' bytecode in KV", module_name_kv);

      auto module_bytecode = modules_bytecode_handle->get(module_name_kv);
      if (!module_bytecode.has_value())
      {
        CCF_APP_TRACE("Module '{}' not found", module_name_kv);
        return std::nullopt;
      }

      auto module_val = ctx.read_object(
        module_bytecode->data(), module_bytecode->size(), JS_READ_OBJ_BYTECODE);

      const bool failed_deser = module_val.is_exception();

      if (failed_deser)
      {
        auto [reason, trace] = ctx.error_message();

        auto& rt = ctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        throw std::runtime_error(fmt::format(
          "Failed to deserialize bytecode for module '{}': {}",
          module_name,
          reason));
      }

      CCF_APP_TRACE(
        "Module '{}' bytecode found in KV (table: {})",
        module_name_kv,
        modules_bytecode_handle->get_name_of_map());
      return module_val;
    }
  };
}
