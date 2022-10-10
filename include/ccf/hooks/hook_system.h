// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/hooks/hook_system.h"
#include "ccf/kv/hooks.h"
#include "ccf/node_subsystem_interface.h"
#include "kv/store.h"

#include <memory>
#include <string>

namespace ccf::hooks
{
  class HookSystem : public ccf::AbstractNodeSubSystem
  {
  protected:
    std::shared_ptr<kv::Store> tables;

  public:
    HookSystem(std::shared_ptr<kv::Store> tables_) : tables(tables_) {}

    static std::string get_subsystem_name()
    {
      return "HookSystem";
    }

    // install a new hook that gets invoked with entries once they have been
    // globally committed (gone through consensus).
    //
    // Returns whether the install overwrote an existing hook.
    bool install_global_hook(
      const std::string& map_name, const kv::untyped::Map::CommitHook& hook)
    {
      // register the hook
      // TODO: check overlapping map names with already registered indexes
      return tables->set_global_hook(map_name, hook);
    }
  };
}