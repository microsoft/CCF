// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "ccf/research/custom_protocol_subsystem_interface.h"
#include "ccf/rpc_context.h"
#include "ccf/service/node_info_network.h"
#include "node/rpc/node_interface.h"

#include <functional>
#include <memory>

namespace ccf
{
  class CustomProtocolSubsystem : public CustomProtocolSubsystemInterface
  {
  protected:
    AbstractNodeState& node_state;
    std::map<std::string, CreateSessionFn> session_creation_functions;

  public:
    CustomProtocolSubsystem(AbstractNodeState& node_state_) :
      node_state(node_state_)
    {}

    virtual void install(
      const std::string& protocol_name,
      CreateSessionFn create_session_f) override
    {
      session_creation_functions[protocol_name] = create_session_f;
    }

    virtual void uninstall(const std::string& protocol_name) override
    {
      session_creation_functions.erase(protocol_name);
    }

    virtual std::shared_ptr<Session> create_session(
      const std::string& protocol_name,
      tls::ConnID conn_id,
      const std::unique_ptr<tls::Context>&& ctx) override
    {
      auto it = session_creation_functions.find(protocol_name);
      if (it != session_creation_functions.end())
      {
        return it->second(conn_id, std::move(ctx));
      }
      else
      {
        throw std::logic_error(fmt::format(
          "Session creation function for protocol '{}' has not been installed",
          protocol_name));
      }
    }
  };
}
