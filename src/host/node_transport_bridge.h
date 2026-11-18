// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "host/node_connections.h"
#include "host/node_frame.h"
#include "node/node_tls.h"

#include <map>
#include <mutex>

namespace asynchost
{
  // Temporary adapter intended for removal with legacy sockets.
  class NodeTransportBridge : public ccf::AbstractNodeTransport
  {
    Ledger& ledger;
    LedgerSubsystem& ledger_subsystem;
    std::shared_ptr<NodeConnections> legacy;
    std::shared_ptr<ccf::NodeTLS> tls;
    std::mutex peers_mutex;
    std::map<ccf::NodeId, const std::optional<std::string>> peers;

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
      std::lock_guard guard(peers_mutex);
      const auto it = peers.find(peer);
      return it != peers.end() && it->second.has_value();
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
      const auto selected_address = tls != nullptr ? address : std::nullopt;
      std::lock_guard guard(peers_mutex);
      const auto [it, inserted] = peers.try_emplace(peer, selected_address);
      if (!inserted && it->second != selected_address)
      {
        throw std::logic_error(fmt::format(
          "Cannot change registered node transport for peer {}", peer));
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
      std::string address;
      {
        std::lock_guard guard(peers_mutex);
        const auto& registered = peers.at(to);
        if (!registered.has_value())
        {
          throw std::logic_error(
            "Cannot send TLS traffic on a registered legacy transport");
        }
        address = *registered;
      }
      return tls->send(
        to,
        type,
        address,
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
