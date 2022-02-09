// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv_module_loader.h"

#include "ccf/tx.h"
#include "service/network_tables.h"

namespace ccf
{
  std::optional<std::string> v8_kv_module_load_callback(
    const std::string& module_name, void* opaque)
  {
    auto tx = static_cast<kv::Tx*>(opaque);
    const auto modules = tx->ro<ccf::Modules>(ccf::Tables::MODULES);
    LOG_TRACE_FMT("Loading module '{}'", module_name);
    auto module = modules->get(module_name);
    return module;
  }
} // namespace ccf