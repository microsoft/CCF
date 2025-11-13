// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/startup_config.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/service/node_info_network.h"

#include <map>
#include <regex>

namespace ccf
{
  struct NodeConfigurationState
  {
    const ccf::StartupConfig& node_config;
    std::map<NodeInfoNetwork::RpcInterfaceID, std::vector<std::regex>>
      rpc_interface_regexes;
    bool initialized = false;
  };

  class NodeConfigurationInterface : public AbstractNodeSubSystem
  {
  public:
    ~NodeConfigurationInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "NodeConfiguration";
    }

    virtual const NodeConfigurationState& get() = 0;
  };
}
