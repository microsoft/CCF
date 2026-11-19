// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/commit_point_interface.h"
#include "node/node_state.h"

#include <memory>

namespace ccf
{
  class CommitPointSubsystem : public AbstractCommitPoint
  {
    std::weak_ptr<NodeState> node;

  public:
    CommitPointSubsystem(const std::shared_ptr<NodeState>& node_) : node(node_)
    {}

    [[nodiscard]] std::optional<ccf::TxID> get_committed_txid() const override
    {
      if (auto owner = node.lock())
      {
        return owner->get_committed_txid();
      }
      return std::nullopt;
    }
  };
}
