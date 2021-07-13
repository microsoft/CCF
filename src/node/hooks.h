// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"

namespace ccf
{
  struct NodeAddr
  {
    std::string hostname;
    std::string port;
  };

  class ConfigurationChangeHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::map<NodeId, std::optional<NodeAddr>> cfg_delta;
    std::unordered_set<NodeId> learners;

  public:
    ConfigurationChangeHook(kv::Version version_, const Nodes::Write& w) :
      version(version_)
    {
      for (const auto& [node_id, opt_ni] : w)
      {
        const auto& ni = opt_ni.value();
        switch (ni.status)
        {
          case NodeStatus::PENDING:
          {
            // Pending nodes are not added to consensus until they are
            // trusted
            break;
          }
          case NodeStatus::TRUSTED:
          {
            cfg_delta.try_emplace(node_id, NodeAddr{ni.nodehost, ni.nodeport});
            break;
          }
          case NodeStatus::RETIRED:
          {
            cfg_delta.try_emplace(node_id, std::nullopt);
            break;
          }
          case NodeStatus::LEARNER:
          {
            cfg_delta.try_emplace(node_id, NodeAddr{ni.nodehost, ni.nodeport});
            learners.insert(node_id);
            break;
          }
          case NodeStatus::RETIRING:
          {
            /* Nothing */
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
      for (const auto& [node_id, opt_ni] : cfg_delta)
      {
        if (opt_ni.has_value())
        {
          configuration.try_emplace(node_id, opt_ni->hostname, opt_ni->port);
        }
        else
        {
          configuration.erase(node_id);
        }
      }
      if (!cfg_delta.empty())
      {
        consensus->add_configuration(version, configuration, learners);
      }
    }
  };

  class NetworkConfigurationsHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::set<kv::NetworkConfiguration> configs;

  public:
    NetworkConfigurationsHook(
      kv::Version version_, const NetworkConfigurations::Write& w) :
      version(version_)
    {
      for (const auto& [rid, opt_nc] : w)
      {
        if (opt_nc.has_value())
        {
          configs.insert(opt_nc.value());
        }
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      for (auto nc : configs)
      {
        consensus->add_network_configuration(version, nc);
      }
    }
  };

}