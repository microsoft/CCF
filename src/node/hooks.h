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

  public:
    NodeChangeHook(ccf::SeqNo seq_no, const Nodes::Write& w)
    {
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
    }
  };

  class ConfigurationChangeHook : public kv::ConsensusHook
  {
    std::list<kv::Configuration> configurations;

  public:
    ConfigurationChangeHook(
      ccf::SeqNo seq_no, const NetworkConfigurations::Write& w)
    {
      // Note: if multiple configurations are added in one transaction, then
      // they are assigned the same id/seq_no here.

      for (const auto& [id, opt_cfg] : w)
      {
        kv::Configuration c;
        c.seq_no = seq_no;
        if (opt_cfg.has_value())
        {
          for (const auto& node_id : opt_cfg.value().nodes)
          {
            c.nodes.insert(node_id);
          }
        }
        configurations.push_back(std::move(c));
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      for (auto c : configurations)
      {
        consensus->add_configuration(std::move(c));
      }
    }
  };
}