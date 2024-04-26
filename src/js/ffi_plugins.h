// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js_plugin.h"
#include "ccf/version.h"

#include <vector>

namespace ccf::js
{
  extern std::vector<FFIPlugin> ffi_plugins;

  static inline void register_ffi_plugin(const FFIPlugin& plugin)
  {
    if (plugin.ccf_version != std::string(ccf::ccf_version))
    {
      throw std::runtime_error(fmt::format(
        "CCF version mismatch in JS FFI plugin '{}': expected={} != actual={}",
        plugin.name,
        plugin.ccf_version,
        ccf::ccf_version));
    }
    LOG_DEBUG_FMT("JS FFI plugin registered: {}", plugin.name);
    ffi_plugins.push_back(plugin);
  }

  static inline void register_ffi_plugins(const std::vector<FFIPlugin>& plugins)
  {
    for (const auto& plugin : plugins)
    {
      register_ffi_plugin(plugin);
    }
  }
}