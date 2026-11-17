// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/node_to_node_channel_manager.h"

namespace ccf
{
  // Temporary bridge until legacy channels are removed. Selection depends only
  // on configuration and recorded metadata, never on a connection outcome.
  class NodeChannelBridge : public NodeToNodeChannelManager
  {
    std::shared_ptr<AbstractNodeTransport> transport;
    NodeId self;
    crypto::Pem service;
    crypto::ECKeyPairPtr key;

  public:
    explicit NodeChannelBridge(
      std::shared_ptr<AbstractNodeTransport> transport_) :
      NodeToNodeChannelManager(transport_),
      transport(std::move(transport_))
    {}

    void initialize(
      const NodeId& self_,
      const crypto::Pem& service_,
      crypto::ECKeyPairPtr key_,
      const std::optional<crypto::Pem>& cert) override
    {
      NodeToNodeChannelManager::initialize(self_, service_, key_, cert);
      self = self_;
      service = service_;
      key = std::move(key_);
      if (cert)
      {
        transport->set_tls_identity(service, key, *cert);
      }
    }

    void set_endorsed_node_cert(const crypto::Pem& cert) override
    {
      NodeToNodeChannelManager::set_endorsed_node_cert(cert);
      transport->set_tls_identity(service, key, cert);
    }

    void associate_node_tls_address(
      const NodeId& peer, const std::optional<std::string>& address) override
    {
      transport->associate_tls_address(peer, address);
    }

    void close_channel(const NodeId& peer) override
    {
      NodeToNodeChannelManager::close_channel(peer);
      transport->close_tls(peer);
    }

    bool send_authenticated(
      const NodeId& to,
      NodeMsgType type,
      const uint8_t* data,
      size_t size) override
    {
      if (!transport->uses_tls(to))
      {
        return NodeToNodeChannelManager::send_authenticated(
          to, type, data, size);
      }
      transport->send_tls(
        to, type, self, std::vector<uint8_t>(data, data + size));
      return true;
    }

    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      std::span<const uint8_t> header,
      const std::vector<uint8_t>& data) override
    {
      if (!transport->uses_tls(to))
      {
        return NodeToNodeChannelManager::send_encrypted(to, type, header, data);
      }
      std::vector<uint8_t> payload(header.begin(), header.end());
      payload.insert(payload.end(), data.begin(), data.end());
      transport->send_tls(to, type, self, std::move(payload));
      return true;
    }
  };
}
