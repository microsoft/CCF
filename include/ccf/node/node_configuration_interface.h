// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  class NodeConfigurationInterface : public AbstractNodeSubSystem
  {
  public:
    ~NodeConfigurationInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "NodeConfiguration";
    }

    /// Returns the free-form node data supplied by the operator in the node
    /// configuration, or null if none was provided.
    virtual const nlohmann::json& get_node_data() = 0;
  };
}
