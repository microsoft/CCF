// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "channels.h"
#include "ds/logger.h"
#include "ds/serialized.h"
#include "enclave/rpc_handler.h"
#include "node_types.h"

#include <algorithm>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf
{
  class NodeToNode
  {
  public:
    virtual ~NodeToNode() = default;

    class DroppedMessageException : public std::exception
    {
    public:
      NodeId from;
      DroppedMessageException(const NodeId& from) : from(from) {}
    };

    virtual void create_channel(
      const NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service,
      size_t message_limit = Channel::default_message_limit) = 0;

    virtual void destroy_channel(const NodeId& peer_id) = 0;

    virtual void close_all_outgoing() = 0;

    virtual void destroy_all_channels() = 0;

    virtual bool have_channel(const NodeId& nid) const = 0;

    template <class T>
    bool send_authenticated(const NodeId& to, NodeMsgType type, const T& data)
    {
      return send_authenticated(
        to, type, reinterpret_cast<const uint8_t*>(&data), sizeof(T));
    }

    template <>
    bool send_authenticated(
      const NodeId& to, NodeMsgType type, const std::vector<uint8_t>& data)
    {
      return send_authenticated(to, type, data.data(), data.size());
    }

    virtual bool send_authenticated(
      const NodeId& to, NodeMsgType type, const uint8_t* data, size_t size) = 0;

    template <class T>
    const T& recv_authenticated(
      const NodeId& from, const uint8_t*& data, size_t& size)
    {
      auto& t = serialized::overlay<T>(data, size);

      if (!recv_authenticated(from, asCb(t), data, size))
      {
        throw DroppedMessageException(from);
      }

      return t;
    }

    template <class T>
    const T& recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size)
    {
      const auto* data_ = data;
      auto size_ = size;

      const auto& t = serialized::overlay<T>(data_, size_);

      if (!recv_authenticated_with_load(from, data, size))
      {
        throw DroppedMessageException(from);
      }
      serialized::skip(data, size, sizeof(T));

      return t;
    }

    virtual bool recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size) = 0;

    virtual bool recv_authenticated(
      const NodeId& from, CBuffer cb, const uint8_t*& data, size_t& size) = 0;

    virtual void recv_message(
      const NodeId& from, const uint8_t* data, size_t size) = 0;

    virtual void initialize(
      const NodeId& self_id,
      const crypto::Pem& network_cert,
      crypto::KeyPairPtr node_kp,
      const crypto::Pem& node_cert) = 0;

    virtual bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      CBuffer cb,
      const std::vector<uint8_t>& data) = 0;

    template <class T>
    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      const std::vector<uint8_t>& data,
      const T& msg_hdr)
    {
      return send_encrypted(to, type, asCb(msg_hdr), data);
    }

    template <class T>
    std::pair<T, std::vector<uint8_t>> recv_encrypted(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      auto t = serialized::read<T>(data, size);

      std::vector<uint8_t> plain = recv_encrypted(from, asCb(t), data, size);
      return std::make_pair(t, plain);
    }

    virtual std::vector<uint8_t> recv_encrypted(
      const NodeId& from, CBuffer cb, const uint8_t* data, size_t size) = 0;
  };

  class NodeToNodeImpl : public NodeToNode
  {
  private:
    std::optional<NodeId> self = std::nullopt;
    std::unique_ptr<ChannelManager> channels;
    ringbuffer::AbstractWriterFactory& writer_factory;

  public:
    NodeToNodeImpl(ringbuffer::AbstractWriterFactory& writer_factory_) :
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
      size_t message_limit = Channel::default_message_limit) override
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

    void close_all_outgoing() override
    {
      channels->close_all_outgoing();
    }

    void destroy_all_channels() override
    {
      channels->destroy_all_channels();
    }

    bool have_channel(const NodeId& nid) const override
    {
      return channels->have_channel(nid);
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

    void recv_message(
      const NodeId& from, const uint8_t* data, size_t size) override
    {
      try
      {
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
