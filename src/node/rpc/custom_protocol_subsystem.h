// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "ccf/rpc_context.h"
#include "ccf/service/node_info_network.h"
#include "node/rpc/custom_protocol_subsystem_interface.h"
#include "node/rpc/node_interface.h"

#include <functional>
#include <memory>

namespace ccf
{
  class CustomProtocolSubsystem : public CustomProtocolSubsystemInterface
  {
  protected:
    AbstractNodeState& node_state;

  public:
    std::map<NodeInfoNetwork::RpcInterfaceID, create_session_ft>
      session_creation_functions;

    CustomProtocolSubsystem(AbstractNodeState& node_state_) :
      node_state(node_state_)
    {}

    virtual void install(
      const NodeInfoNetwork::RpcInterfaceID& interface_id,
      create_session_ft create_session_f) override
    {
      session_creation_functions[interface_id] = create_session_f;
    }

    virtual void uninstall(
      const NodeInfoNetwork::RpcInterfaceID& interface_id) override
    {
      session_creation_functions.erase(interface_id);
    }
  };
}
