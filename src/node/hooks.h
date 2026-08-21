// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/node_info_network.h"
#include "ccf/service/reconfiguration_type.h"
#include "ds/internal_logger.h"
#include "service/tables/config.h"
#include "service/tables/signatures.h"

#include <stdexcept>

namespace ccf
{
  class ConfigurationChangeHook : public ccf::kv::ConsensusHook
  {
    ccf::kv::Version version;
    ccf::kv::Configuration::NodeChanges cfg_delta;

  public:
    ConfigurationChangeHook(ccf::kv::Version version_, const Nodes::Write& w) :
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
            cfg_delta.try_emplace(
              node_id, ccf::kv::Configuration::NodeInfo{host, port});
            break;
          }
          case NodeStatus::RETIRED:
          {
            cfg_delta.try_emplace(node_id, std::nullopt);
            break;
          }
          default:
          {
            throw std::logic_error(fmt::format(
              "Unknown node status {} for node {} in configuration change hook",
              static_cast<uint8_t>(ni.status),
              node_id));
          }
        }
      }
    }

    void call(ccf::kv::ConfigurableConsensus* consensus) override
    {
      consensus->update_configuration(version, cfg_delta);
    }
  };
}
