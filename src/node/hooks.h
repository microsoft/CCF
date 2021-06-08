// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "kv/kv_types.h"
#include "node/network_configurations.h"
#include "node/nodes.h"

namespace ccf
{
  class NodeChangeHook : public kv::ConsensusHook
  {
    std::unordered_map<NodeId, std::optional<ccf::NodeInfo>> updates;
    SeqNo seq_no;

  public:
    NodeChangeHook(ccf::SeqNo seq_no, const Nodes::Write& w)
    {
      this->seq_no = seq_no;
      for (const auto& [id, info] : w)
      {
        updates.emplace(id, info);
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      for (const auto& [id, info] : updates)
      {
        consensus->update_node(id, info);
      }

      auto ltst = consensus->get_latest_configuration_unsafe();
      kv::Configuration c;
      c.seq_no = seq_no;
      c.nodes = ltst;
      for (const auto& [id, info] : updates)
      {
        if (
          info->status == NodeStatus::CATCHING_UP ||
          info->status == NodeStatus::TRUSTED)
        {
          c.nodes.insert(id);
        }
        else if (info->status == NodeStatus::RETIRED)
        {
          c.nodes.erase(id);
        }
      }
      if (c.nodes != ltst)
        consensus->add_configuration(std::move(c));
    }
  };
}