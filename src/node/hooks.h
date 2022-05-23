// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/service/node_info_network.h"
#include "enclave/reconfiguration_type.h"
#include "service/tables/config.h"
#include "service/tables/signatures.h"

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
    std::unordered_set<NodeId> retired_nodes;

  public:
    ConfigurationChangeHook(kv::Version version_, const Nodes::Write& w) :
      version(version_)
    {
      for (const auto& [node_id, opt_ni] : w)
      {
        if (!opt_ni.has_value())
        {
          // Deleted node will have already been retired
          continue;
        }

        const auto& ni = opt_ni.value();
        const auto [host, port] =
          split_net_address(ni.node_to_node_interface.published_address);
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
            cfg_delta.try_emplace(node_id, NodeAddr{host, port});
            break;
          }
          case NodeStatus::RETIRED:
          {
            cfg_delta.try_emplace(node_id, std::nullopt);
            retired_nodes.insert(node_id);
            break;
          }
          case NodeStatus::LEARNER:
          {
            cfg_delta.try_emplace(node_id, NodeAddr{host, port});
            learners.insert(node_id);
            break;
          }
          case NodeStatus::RETIRING:
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
        consensus->add_configuration(
          version, configuration, learners, retired_nodes);
      }
    }
  };

  inline void service_configuration_commit_hook(
    kv::Version version,
    const ccf::Configuration::Write& w,
    const std::shared_ptr<kv::Consensus>& consensus)
  {
    LOG_DEBUG_FMT("Service configuration update hook");
    assert(w.has_value());
    auto new_service_config = w.value();
    kv::ConsensusParameters cp;
    cp.reconfiguration_type = new_service_config.reconfiguration_type.value_or(
      ReconfigurationType::ONE_TRANSACTION);
    consensus->update_parameters(cp);
  }
}
