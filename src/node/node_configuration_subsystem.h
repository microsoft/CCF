// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "node/rpc/node_interface.h"

namespace ccf
{
  class NodeConfigurationSubsystem : public AbstractNodeSubSystem
  {
  protected:
    AbstractNodeState& node_state;

  public:
    NodeConfigurationSubsystem(AbstractNodeState& node_state_) :
      node_state(node_state_)
    {}

    virtual ~NodeConfigurationSubsystem() = default;

    static char const* get_subsystem_name()
    {
      return "NodeConfiguration";
    }

    virtual const StartupConfig& get()
    {
      return node_state.get_node_config();
    }
  };
}
