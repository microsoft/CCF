// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "kv/kv_types.h"
#include "node/nodes.h"

namespace ccf
{
  struct NodeAddr
  {
    std::string hostname;
    std::string port;
    bool catching_up;
  };

  class ConfigurationChangeHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::map<NodeId, std::optional<NodeAddr>> cfg_delta;

  public:
    ConfigurationChangeHook(kv::Version version_, const Nodes::Write& w) :
      version(version_)
    {
      for (const auto& [node_id, opt_ni] : w)
      {
        LOG_TRACE_FMT("ConfigurationChangeHook(): {}", node_id);

        const auto& ni = opt_ni.value();
        switch (ni.status)
        {
          case NodeStatus::PENDING:
          {
            // Pending nodes are not added to consensus until they are
            // trusted
            break;
          }
          case NodeStatus::CATCHING_UP:
          {
            cfg_delta.try_emplace(
              node_id, NodeAddr{ni.nodehost, ni.nodeport, true});
            break;
          }
          case NodeStatus::TRUSTED:
          {
            cfg_delta.try_emplace(
              node_id, NodeAddr{ni.nodehost, ni.nodeport, false});
            break;
          }
          case NodeStatus::RETIRED:
          {
            cfg_delta.try_emplace(node_id, std::nullopt);
            break;
          }
          default:
          {
          }
        }
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      auto configuration = consensus->get_latest_configuration_unsafe();

      LOG_INFO_FMT("ConfigurationChangeHook::call()");

      for (const auto& [node_id, opt_ni] : cfg_delta)
      {
        if (opt_ni.has_value())
        {
          LOG_INFO_FMT(
            "+ {} {}",
            node_id,
            (opt_ni->catching_up ? "catching up" : "trusted"));
          configuration[node_id] = {
            opt_ni->hostname, opt_ni->port, opt_ni->catching_up};
        }
        else
        {
          LOG_INFO_FMT("- {}", node_id);
          configuration.erase(node_id);
        }
      }

      if (!cfg_delta.empty())
      {
        consensus->add_configuration(version, configuration);
      }
    }
  };
}