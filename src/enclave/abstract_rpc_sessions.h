// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/service/node_info_network.h"
#include "enclave/client_session.h"
#include "forwarder_types.h"
#include "node/session_metrics.h"

#include <memory>
#include <string>

namespace tls
{
  class Cert;
}

namespace ccf
{
  class CustomProtocolSubsystem;
  class CommitCallbackSubsystem;

  // The slice of RPC session management that the node (NodeState, frontends,
  // Enclave, jwt refresh) depends on, independent of how connections are
  // actually serviced. Both the legacy RPCSessions (ringbuffer/host-split) and
  // the new host-side RPCConnectionManager implement this, so node-side code can
  // hold a reference without depending on the concrete networking backend.
  class AbstractRPCSessions : public AbstractRPCResponder
  {
  public:
    ~AbstractRPCSessions() override = default;

    // Outbound client sessions (join, JWT refresh, redirects).
    virtual std::shared_ptr<ClientSession> create_client(
      const std::shared_ptr<::tls::Cert>& cert,
      const std::string& app_protocol = "HTTP1") = 0;

    virtual ccf::ApplicationProtocol get_app_protocol_main_interface()
      const = 0;

    virtual ccf::SessionMetrics get_session_metrics() = 0;

    virtual void set_node_cert(
      const ccf::crypto::Pem& cert, const ccf::crypto::Pem& pk) = 0;
    virtual void set_network_cert(
      const ccf::crypto::Pem& cert, const ccf::crypto::Pem& pk) = 0;

    virtual void update_listening_interface_options(
      const ccf::NodeInfoNetwork& node_info) = 0;

    virtual void set_custom_protocol_subsystem(
      std::shared_ptr<CustomProtocolSubsystem> cpss) = 0;
    virtual void set_commit_callbacks_subsystem(
      std::shared_ptr<CommitCallbackSubsystem> fcss) = 0;
  };
}
