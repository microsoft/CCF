// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "host/node_connections.h"
#include "host/node_frame.h"
#include "node/node_tls.h"

namespace asynchost
{
  // Temporary bridge until legacy sockets are removed.
  class NodeTransportBridge : public ccf::AbstractNodeTransport
  {
    Ledger& ledger;
    LedgerSubsystem& ledger_subsystem;
    std::shared_ptr<NodeConnections> legacy;
    std::shared_ptr<ccf::NodeTLS> tls;

  public:
    NodeTransportBridge(
      Ledger& ledger_,
      LedgerSubsystem& ledger_subsystem_,
      std::shared_ptr<NodeConnections> legacy_,
      std::shared_ptr<ccf::NodeTLS> tls_) :
      ledger(ledger_),
      ledger_subsystem(ledger_subsystem_),
      legacy(std::move(legacy_)),
      tls(std::move(tls_))
    {}

    bool uses_tls(const ccf::NodeId& peer) override
    {
      return tls != nullptr && tls->enabled_for(peer);
    }

    void stop_tls() override
    {
      if (tls != nullptr)
      {
        tls->stop();
      }
    }

    void associate_tls_address(
      const ccf::NodeId& peer,
      const std::optional<std::string>& address) override
    {
      if (tls != nullptr)
      {
        tls->associate(peer, address);
      }
    }

    void set_tls_identity(
      const ccf::crypto::Pem& service,
      ccf::crypto::ECKeyPairPtr key,
      const ccf::crypto::Pem& cert) override
    {
      if (tls != nullptr)
      {
        tls->set_identity(service, std::move(key), cert);
      }
    }

    void associate_node_address(
      const ccf::NodeId& peer,
      const std::string& host,
      const std::string& port) override
    {
      legacy->associate_node_address(peer, host, port);
    }

    void send(
      const ccf::NodeId& to,
      ccf::NodeMsgType type,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload) override
    {
      legacy->send(to, type, from, std::move(payload));
    }

    bool send_tls(
      const ccf::NodeId& to,
      ccf::NodeMsgType type,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload) override
    {
      return tls->send(
        to,
        type,
        [this, to, type, from, payload = std::move(payload)](
          ::tcp::ConnID id) mutable {
          send_node_frame(
            ledger,
            ledger_subsystem,
            to,
            type,
            from,
            std::move(payload),
            [tls = tls, id](std::vector<uint8_t>&& frame) {
              tls->send_frame(id, std::move(frame));
            });
        });
    }

    void close(const ccf::NodeId& peer) override
    {
      legacy->close(peer);
    }

    void close_tls(const ccf::NodeId& peer) override
    {
      if (tls != nullptr)
      {
        tls->close(peer);
      }
    }

    void set_inbound_handler(
      std::shared_ptr<ccf::NodeInboundHandler> handler) override
    {
      legacy->set_inbound_handler(handler);
      if (tls != nullptr)
      {
        tls->set_handler(std::move(handler));
      }
    }
  };
}
