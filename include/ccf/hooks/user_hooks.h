// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/hooks.h"
#include "ccf/kv/untyped.h"
#include "ccf/node_subsystem_interface.h"

#include <memory>
#include <string>

namespace ccf::hooks
{
  class UserHooks : public ccf::AbstractNodeSubSystem
  {
  public:
    UserHooks() = default;

    static std::string get_subsystem_name()
    {
      return "UserHooks";
    }

    // Install a new hook that gets invoked with entries once they have been
    // globally committed (gone through consensus).
    //
    // Returns whether the install overwrote an existing hook.
    virtual bool install_global_hook(
      const std::string& map_name, const kv::untyped::CommitHook& hook) = 0;
  };
}