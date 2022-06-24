// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "node/rpc/node_interface.h"

#include <regex>

namespace ccf
{
  struct NodeConfigurationState
  {
    const StartupConfig& node_config;
    std::map<NodeInfoNetwork::RpcInterfaceID, std::vector<std::regex>>
      rpc_interface_regexes;
    bool initialized = false;
  };

  class NodeConfigurationSubsystem : public AbstractNodeSubSystem
  {
  protected:
    AbstractNodeState& node_state;
    NodeConfigurationState node_config_state;

  public:
    NodeConfigurationSubsystem(AbstractNodeState& node_state_) :
      node_state(node_state_),
      node_config_state({node_state_.get_node_config(), {}, false})
    {}

    virtual ~NodeConfigurationSubsystem() = default;

    static char const* get_subsystem_name()
    {
      return "NodeConfiguration";
    }

    virtual const NodeConfigurationState& get()
    {
      if (!node_config_state.initialized)
      {
        initialize_interface_regexes();
        node_config_state.initialized = true;
      }
      return node_config_state;
    }

    void initialize_interface_regexes()
    {
      for (const auto& [id, interface] :
           node_config_state.node_config.network.rpc_interfaces)
      {
        LOG_TRACE_FMT("Check regex: {}", id);
        if (interface.accepted_endpoints)
        {
          auto [it, ok] = node_config_state.rpc_interface_regexes.emplace(
            id, std::vector<std::regex>{});
          if (!ok)
          {
            throw std::runtime_error("Could not emplace interface regexes");
          }
          for (const auto& re : *interface.accepted_endpoints)
          {
            LOG_TRACE_FMT(
              "Add accepted endpoint regex to interface config: {}", re);
            it->second.emplace_back(re);
          }
        }
      }
    }
  };
}
