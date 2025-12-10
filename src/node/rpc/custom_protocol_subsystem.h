// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_context.h"
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
      const std::unique_ptr<tls::Context>&& ctx) override
    {
      auto it = session_creation_functions.find(protocol_name);
      if (it != session_creation_functions.end())
      {
        return it->second(conn_id, std::move(ctx));
      }
      throw std::logic_error(fmt::format(
        "Session creation function for protocol '{}' has not been installed",
        protocol_name));
    }

    std::shared_ptr<Essentials> get_essentials() override
    {
      std::shared_ptr<Essentials> r = std::make_shared<Essentials>();
      r->writer = node_state.get_writer_factory().create_writer_to_outside();
      auto store = node_state.get_store();
      r->tx = std::make_shared<ccf::kv::ReadOnlyTx>(store.get());
      r->ctx = std::make_shared<ccf::endpoints::ReadOnlyEndpointContext>(
        nullptr, *r->tx);
      return r;
    }
  };
}
