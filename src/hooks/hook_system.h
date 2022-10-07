// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/kv/hooks.h"
#include "ccf/node_subsystem_interface.h"
#include "kv/kv_types.h"
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
    bool install_global_hook(
      const std::string& map_name, const kv::untyped::Map::CommitHook& hook)
    {
      // register the hook
      // TODO: check overlapping map names with already registered indexes
      tables->set_global_hook(
        map_name,
        [hook](kv::Version version, const kv::untyped::Write& writes) {
          // invoke the handle_committed_transaction handler
          // TODO: get the actual raft term
          //   ccf::TxID tx_id{0, version};
          hook(version, writes);
        });

      return true;
    }
  };
}