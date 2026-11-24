// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/node_configuration_interface.h"
#include "node/rpc/node_interface.h"

#include <regex>
#include <stdexcept>

namespace ccf
{
  class NodeConfigurationSubsystem : public NodeConfigurationInterface
  {
  public:
    using InterfaceRegexes =
      decltype(NodeConfigurationState::rpc_interface_regexes);

  protected:
    AbstractNodeState& node_state;
    NodeConfigurationState node_config_state;

  public:
    // The node configuration is only set when the node is created, after this
    // subsystem is installed, so the interface regexes are built beforehand,
    // from the configuration, with build_interface_regexes().
    NodeConfigurationSubsystem(
      AbstractNodeState& node_state_, InterfaceRegexes interface_regexes) :
      node_state(node_state_),
      node_config_state(
        {node_state_.get_node_config(),
         node_state_.get_node_data(),
         std::move(interface_regexes),
         true})
    {}

    ~NodeConfigurationSubsystem() override = default;

    static char const* get_subsystem_name()
    {
      return "NodeConfiguration";
    }

    const NodeConfigurationState& get() override
    {
      return node_config_state;
    }

    virtual bool has_received_stop_notice()
    {
      return node_state.has_received_stop_notice();
    }

    // Throws std::invalid_argument if a pattern isn't a valid regular
    // expression.
    static InterfaceRegexes build_interface_regexes(
      const NodeInfoNetwork::RpcInterfaces& rpc_interfaces)
    {
      InterfaceRegexes regexes;
      for (const auto& [id, interface] : rpc_interfaces)
      {
        if (interface.accepted_endpoints)
        {
          auto& interface_regexes = regexes[id];
          for (const auto& re : *interface.accepted_endpoints)
          {
            try
            {
              interface_regexes.emplace_back(re);
            }
            catch (const std::regex_error& e)
            {
              throw std::invalid_argument(fmt::format(
                "Invalid accepted_endpoints pattern '{}' for RPC interface "
                "'{}': {}",
                re,
                id,
                e.what()));
            }
          }
        }
      }
      return regexes;
    }
  };
}
