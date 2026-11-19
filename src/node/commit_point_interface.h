// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "ccf/tx_id.h"

#include <optional>

namespace ccf
{
  class AbstractCommitPoint : public AbstractNodeSubSystem
  {
  public:
    static char const* get_subsystem_name()
    {
      return "CommitPoint";
    }

    // No usable commit point is available until private recovery is complete
    // and the node is part of the network, or after its owner is destroyed.
    [[nodiscard]] virtual std::optional<ccf::TxID> get_committed_txid()
      const = 0;
  };
}
