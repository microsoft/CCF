// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv_module_loader.h"

#include "ccf/tx.h"
#include "node/entities.h"
#include "node/modules.h"

namespace ccf
{
  std::optional<std::string> v8_kv_module_load_callback(
    const std::string& module_name, void* opaque)
  {
    auto tx = (kv::Tx*)opaque;
    const auto modules = tx->ro<ccf::Modules>(ccf::Tables::MODULES);
    LOG_TRACE_FMT("Loading module '{}'", module_name);
    auto module = modules->get(module_name_kv);
    return module;
  }
} // namespace ccf