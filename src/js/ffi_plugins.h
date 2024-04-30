// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js_plugin.h"

#include <vector>

namespace ccf::js
{
  extern std::vector<FFIPlugin> ffi_plugins;

  void register_ffi_plugin(const FFIPlugin& plugin);

  static inline void register_ffi_plugins(const std::vector<FFIPlugin>& plugins)
  {
    for (const auto& plugin : plugins)
    {
      register_ffi_plugin(plugin);
    }
  }
}