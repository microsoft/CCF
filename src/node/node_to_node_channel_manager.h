// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "channel.h"
#include "node/node_to_node.h"

namespace ccf
{
  class NodeToNodeChannelManager : public NodeToNode
  {
  private:
    std::optional<NodeId> self = std::nullopt;
    std::unique_ptr<ChannelManager> channels;
    ringbuffer::AbstractWriterFactory& writer_factory;

  public:
    NodeToNodeChannelManager(
      ringbuffer::AbstractWriterFactory& writer_factory_) :
      writer_factory(writer_factory_)
    {}

    void initialize(
      const NodeId& self_id,
      const crypto::Pem& network_cert,
      crypto::KeyPairPtr node_kp,
      const crypto::Pem& node_cert) override
    {
      CCF_ASSERT_FMT(
        !self.has_value(),
        "Calling initialize more than once, previous id:{}, new id:{}",
        self.value(),
        self_id);

      if (make_verifier(node_cert)->is_self_signed())
      {
        LOG_INFO_FMT(
          "Refusing to initialize node-to-node channels with self-signed node "
          "certificate.");
        return;
      }

      self = self_id;
      channels = std::make_unique<ChannelManager>(
        writer_factory, network_cert, node_kp, node_cert, self.value());
    }

    void create_channel(
      const NodeId& peer_id,
      const std::string& hostname,
      const std::string& service,
      std::optional<size_t> message_limit = std::nullopt) override
    {
      if (peer_id == self.value())
      {
        return;
      }

      channels->create_channel(peer_id, hostname, service, message_limit);
    }

    void destroy_channel(const NodeId& peer_id) override
    {
      if (peer_id == self.value())
      {
        return;
      }

      channels->destroy_channel(peer_id);
    }

    void destroy_all_channels() override
    {
      channels->destroy_all_channels();
    }

    bool send_authenticated(
      const NodeId& to,
      NodeMsgType type,
      const uint8_t* data,
      size_t size) override
    {
      auto n2n_channel = channels->get(to);
      return n2n_channel->send(type, {data, size});
    }

    bool recv_authenticated(
      const NodeId& from,
      CBuffer cb,
      const uint8_t*& data,
      size_t& size) override
    {
      auto n2n_channel = channels->get(from);
      // Receiving after a channel has been destroyed is ok.
      return n2n_channel ? n2n_channel->recv_authenticated(cb, data, size) :
                           true;
    }

    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      CBuffer cb,
      const std::vector<uint8_t>& data) override
    {
      auto n2n_channel = channels->get(to);
      return n2n_channel ? n2n_channel->send(type, cb, data) : true;
    }

    bool recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size) override
    {
      auto n2n_channel = channels->get(from);
      return n2n_channel ?
        n2n_channel->recv_authenticated_with_load(data, size) :
        true;
    }

    std::vector<uint8_t> recv_encrypted(
      const NodeId& from, CBuffer cb, const uint8_t* data, size_t size) override
    {
      auto n2n_channel = channels->get(from);

      if (!n2n_channel)
        return {};

      auto plain = n2n_channel->recv_encrypted(cb, data, size);
      if (!plain.has_value())
      {
        throw DroppedMessageException(from);
      }

      return plain.value();
    }

    void process_key_exchange_init(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      LOG_DEBUG_FMT("key_exchange_init from {}", from);

      // In the case of concurrent key_exchange_init's from both nodes, the one
      // with the lower ID wins.

      auto n2n_channel = channels->get(from);
      if (n2n_channel)
        n2n_channel->consume_initiator_key_share(data, size, self < from);
    }

    void process_key_exchange_response(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      LOG_DEBUG_FMT("key_exchange_response from {}", from);
      auto n2n_channel = channels->get(from);
      if (n2n_channel)
        n2n_channel->consume_responder_key_share(data, size);
    }

    void process_key_exchange_final(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      LOG_DEBUG_FMT("key_exchange_final from {}", from);
      auto n2n_channel = channels->get(from);
      if (
        n2n_channel && !n2n_channel->check_peer_key_share_signature(data, size))
      {
        n2n_channel->reset();
      }
    }

    void recv_message(const NodeId& from, OArray&& oa) override
    {
      try
      {
        const uint8_t* data = oa.data();
        size_t size = oa.size();
        auto chmsg = serialized::read<ChannelMsg>(data, size);
        switch (chmsg)
        {
          case key_exchange_init:
          {
            process_key_exchange_init(from, data, size);
            break;
          }

          case key_exchange_response:
          {
            process_key_exchange_response(from, data, size);
            break;
          }

          case key_exchange_final:
          {
            process_key_exchange_final(from, data, size);
            break;
          }

          default:
          {
          }
          break;
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_EXC(e.what());
        return;
      }
    }
  };
}
