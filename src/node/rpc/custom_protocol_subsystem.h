// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/research/custom_protocol_subsystem_interface.h"
#include "node/rpc/node_interface.h"

#include <format>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>

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

    void install(
      const std::string& protocol_name,
      CreateSessionFn create_session_f) override
    {
      session_creation_functions[protocol_name] = create_session_f;
    }

    void uninstall(const std::string& protocol_name) override
    {
      session_creation_functions.erase(protocol_name);
    }

    std::shared_ptr<Session> create_session(
      const std::string& protocol_name,
      ccf::tls::ConnID conn_id,
      ccf::SessionWriter& writer) override
    {
      auto it = session_creation_functions.find(protocol_name);
      if (it != session_creation_functions.end())
      {
        return it->second(conn_id, writer);
      }
      throw std::logic_error(std::format(
        "Session creation function for protocol '{}' has not been installed",
        protocol_name));
    }

    std::shared_ptr<Essentials> get_essentials() override
    {
      std::shared_ptr<Essentials> r = std::make_shared<Essentials>();
      auto store = node_state.get_store();
      r->tx = std::make_shared<ccf::kv::ReadOnlyTx>(store.get());
      r->ctx = std::make_shared<ccf::endpoints::ReadOnlyEndpointContext>(
        nullptr, *r->tx);
      return r;
    }
  };
}
