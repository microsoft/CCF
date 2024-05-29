// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/wrapped_value.h"

#include <memory>
#include <optional>
#include <vector>

namespace ccf::js
{
  namespace core
  {
    class Context;
  }

  namespace modules
  {
    class ModuleLoaderInterface
    {
    public:
      virtual ~ModuleLoaderInterface() = default;

      virtual std::optional<js::core::JSWrappedValue> get_module(
        std::string_view module_name, js::core::Context& ctx) = 0;
    };

    using ModuleLoaderPtr = std::shared_ptr<ModuleLoaderInterface>;
    using ModuleLoaders = std::vector<ModuleLoaderPtr>;
  }
}
