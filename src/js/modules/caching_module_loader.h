// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/modules/chained_module_loader.h"

#include <map>
#include <string>

namespace ccf::js::modules
{
  class CachingModuleLoader : public ChainedModuleLoader
  {
  protected:
    // The interpreter can cache loaded modules so they do not need to be loaded
    // from the KV for every execution, which is particularly useful when
    // re-using interpreters. A module can only be loaded once per interpreter,
    // and the entire interpreter should be thrown away if _any_ of its modules
    // needs to be refreshed.
    std::map<std::string, js::core::JSWrappedValue, std::less<>>
      loaded_modules_cache;

  public:
    using ChainedModuleLoader::ChainedModuleLoader;

    virtual std::optional<js::core::JSWrappedValue> get_module(
      std::string_view module_name, js::core::Context& ctx) override
    {
      auto it = loaded_modules_cache.find(module_name);
      if (it == loaded_modules_cache.end())
      {
        // If not currently in cache, ask base (chain!)
        auto module_val = ChainedModuleLoader::get_module(module_name, ctx);
        if (module_val.has_value())
        {
          // If base returned a module, store it in cache
          loaded_modules_cache.emplace_hint(it, module_name, *module_val);
        }

        return module_val;
      }

      return it->second;
    }
  };
}
