// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/ffi_plugins.h"

#include "ccf/ds/logger.h"
#include "ccf/version.h"

namespace ccf::js
{
  std::vector<FFIPlugin> ffi_plugins;

  void register_ffi_plugin(const FFIPlugin& plugin)
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
}