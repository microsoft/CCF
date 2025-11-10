// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_context.h"
#include "ccf/node/session.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/rpc_context.h"
#include "ccf/service/node_info_network.h"
#include "ccf/tx.h"

#include <functional>
#include <memory>

namespace ccf
{
  namespace tls
  {
    class Context;
    using ConnID = int64_t;
  }

  class CustomProtocolSubsystemInterface : public AbstractNodeSubSystem
  {
  public:
    using CreateSessionFn = std::function<std::shared_ptr<Session>(
      ccf::tls::ConnID, const std::unique_ptr<tls::Context>&&)>;

    ~CustomProtocolSubsystemInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "Custom Protocol";
    }

    virtual void install(
      const std::string& protocol_name, CreateSessionFn create_session_f) = 0;

    virtual void uninstall(const std::string& protocol_name) = 0;

    virtual std::shared_ptr<Session> create_session(
      const std::string& protocol_name,
      ccf::tls::ConnID conn_id,
      const std::unique_ptr<tls::Context>&& ctx) = 0;

    struct Essentials
    {
      ringbuffer::WriterPtr writer;
      std::shared_ptr<ccf::kv::ReadOnlyTx> tx;
      std::shared_ptr<ccf::endpoints::ReadOnlyEndpointContext> ctx;
    };

    virtual std::shared_ptr<Essentials> get_essentials() = 0;
  };
}
