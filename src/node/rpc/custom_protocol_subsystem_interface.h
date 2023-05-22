// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/rpc_context.h"
#include "ccf/service/node_info_network.h"

#include <functional>
#include <memory>

namespace tls
{
  class Context;
  using ConnID = int64_t;
}

namespace ccf
{
  class CustomProtocolSubsystemInterface : public AbstractNodeSubSystem
  {
  public:
    typedef std::function<std::shared_ptr<Session>(
      tls::ConnID, const std::unique_ptr<tls::Context>&&)>
      create_session_ft;

    virtual ~CustomProtocolSubsystemInterface() = default;

    static char const* get_subsystem_name()
    {
      return "Custom Protocol";
    }

    virtual void install(
      const NodeInfoNetwork::RpcInterfaceID& interface_id,
      CreateSessionFn create_session_f) = 0;

    virtual void uninstall(
      const NodeInfoNetwork::RpcInterfaceID& interface_id) = 0;
  };
}
