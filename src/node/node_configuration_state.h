// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/node_configuration_interface.h"
#include "ccf/service/node_info_network.h"
#include "node/configuration.h"

#include <map>
#include <regex>
#include <vector>

namespace ccf
{
  struct NodeConfigurationState
  {
    const ccf::CCFConfig& node_config;
    const nlohmann::json& node_data;
    std::map<NodeInfoNetwork::RpcInterfaceID, std::vector<std::regex>>
      rpc_interface_regexes;
    bool initialized = false;
  };

  // Internal extension of the public NodeConfigurationInterface, giving the
  // framework access to the full node configuration.
  class NodeConfigurationStateInterface : public NodeConfigurationInterface
  {
  public:
    ~NodeConfigurationStateInterface() override = default;

    virtual const NodeConfigurationState& get() = 0;

    const nlohmann::json& get_node_data() override
    {
      return get().node_data;
    }
  };
}
