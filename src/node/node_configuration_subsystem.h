// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/node_configuration_interface.h"
#include "node/rpc/node_interface.h"

#include <mutex>
#include <regex>
#include <stdexcept>

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
      node_config_state(
        {node_state_.get_node_config(), node_state_.get_node_data(), {}, false})
    {}

    ~NodeConfigurationSubsystem() override = default;

    static char const* get_subsystem_name()
    {
      return "NodeConfiguration";
    }

    // The node configuration is only set when the node is created, after this
    // subsystem is installed, so the interface regexes are built on the first
    // call. Several threads may make that call, so they are built exactly once.
    const NodeConfigurationState& get() override
    {
      std::call_once(
        interface_regexes_built, [this] { initialize_interface_regexes(); });
      return node_config_state;
    }

    virtual bool has_received_stop_notice()
    {
      return node_state.has_received_stop_notice();
    }

  private:
    std::once_flag interface_regexes_built;

    void initialize_interface_regexes()
    {
      // Built separately and only published once complete, so an invalid
      // pattern leaves no partial state behind.
      decltype(node_config_state.rpc_interface_regexes) regexes;
      for (const auto& [id, interface] :
           node_config_state.node_config.network.rpc_interfaces)
      {
        LOG_TRACE_FMT("Check regex: {}", id);
        if (interface.accepted_endpoints)
        {
          auto& interface_regexes = regexes[id];
          for (const auto& re : *interface.accepted_endpoints)
          {
            LOG_TRACE_FMT(
              "Add accepted endpoint regex to interface config: {}", re);
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
      node_config_state.rpc_interface_regexes = std::move(regexes);
      node_config_state.initialized = true;
    }
  };
}
