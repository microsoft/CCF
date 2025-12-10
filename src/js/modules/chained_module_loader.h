// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/modules/module_loader_interface.h"

namespace ccf::js::modules
{
  class ChainedModuleLoader : public ModuleLoaderInterface
  {
  protected:
    ModuleLoaders sub_loaders;

  public:
    ChainedModuleLoader(ModuleLoaders&& ml) : sub_loaders(std::move(ml)) {}

    std::optional<js::core::JSWrappedValue> get_module(
      std::string_view module_name, js::core::Context& ctx) override
    {
      for (auto& sub_loader : sub_loaders)
      {
        auto module_val = sub_loader->get_module(module_name, ctx);
        if (module_val.has_value())
        {
          return module_val;
        }
      }

      return std::nullopt;
    }
  };
}
