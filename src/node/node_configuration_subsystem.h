// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/node_configuration_interface.h"
#include "node/rpc/node_interface.h"

#include <regex>

namespace ccf
{
  class NodeConfigurationSubsystem : public NodeConfigurationInterface
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

    virtual const NodeConfigurationState& get() override
    {
      if (!node_config_state.initialized)
      {
        initialize_interface_regexes();
        node_config_state.initialized = true;
      }
      return node_config_state;
    }

    virtual bool has_received_sigterm()
    {
      return node_state.has_received_sigterm();
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
