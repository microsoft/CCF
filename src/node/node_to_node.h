// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "channels.h"
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

    virtual void create_channel(
      NodeId peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service) = 0;

    virtual void destroy_channel(NodeId peer_id) = 0;

    virtual void close_all_outgoing() = 0;

    virtual void destroy_all_channels() = 0;

    template <class T>
    bool send_authenticated(
      const NodeMsgType& msg_type, NodeId to, const T& data)
    {
      return send_authenticated(
        msg_type, to, reinterpret_cast<const uint8_t*>(&data), sizeof(T));
    }

    template <>
    bool send_authenticated(
      const NodeMsgType& msg_type, NodeId to, const std::vector<uint8_t>& data)
    {
      return send_authenticated(msg_type, to, data.data(), data.size());
    }

    virtual bool send_authenticated(
      const ccf::NodeMsgType& msg_type,
      NodeId to,
      const uint8_t* data,
      size_t size) = 0;

    template <class T>
    const T& recv_authenticated(const uint8_t*& data, size_t& size)
    {
      auto& t = serialized::overlay<T>(data, size);

      if (!recv_authenticated(t.from_node, asCb(t), data, size))
      {
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message from node {}", t.from_node));
      }

      return t;
    }

    template <class T>
    const T& recv_authenticated_with_load(const uint8_t*& data, size_t& size)
    {
      const auto* data_ = data;
      auto size_ = size;

      const auto& t = serialized::overlay<T>(data_, size_);

      if (!recv_authenticated_with_load(t.from_node, data, size))
      {
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message with load from node {}",
          t.from_node));
      }
      serialized::skip(data, size, sizeof(T));

      return t;
    }

    virtual bool recv_authenticated_with_load(
      NodeId from_node, const uint8_t*& data, size_t& size) = 0;

    virtual bool recv_authenticated(
      NodeId from_node, CBuffer cb, const uint8_t*& data, size_t& size) = 0;

    virtual void recv_message(OArray&& oa) = 0;

    virtual void initialize(NodeId self_id, const tls::Pem& network_pkey) = 0;

    virtual bool send_encrypted(
      const NodeMsgType& msg_type,
      CBuffer cb,
      NodeId to,
      const std::vector<uint8_t>& data) = 0;

    template <class T>
    bool send_encrypted(
      const NodeMsgType& msg_type,
      NodeId to,
      const std::vector<uint8_t>& data,
      const T& msg_hdr)
    {
      return send_encrypted(msg_type, asCb(msg_hdr), to, data);
    }

    template <class T>
    std::pair<T, std::vector<uint8_t>> recv_encrypted(
      const uint8_t* data, size_t size)
    {
      auto t = serialized::read<T>(data, size);

      std::vector<uint8_t> plain =
        recv_encrypted(t.from_node, asCb(t), data, size);
      return std::make_pair(t, plain);
    }

    virtual std::vector<uint8_t> recv_encrypted(
      NodeId from_node, CBuffer cb, const uint8_t* data, size_t size) = 0;
  };

  class NodeToNodeImpl : public NodeToNode
  {
  private:
    NodeId self;
    std::unique_ptr<ChannelManager> channels;
    ringbuffer::AbstractWriterFactory& writer_factory;

  public:
    NodeToNodeImpl(ringbuffer::AbstractWriterFactory& writer_factory_) :
      self(INVALID_ID),
      writer_factory(writer_factory_)
    {}

    void initialize(NodeId self_id, const tls::Pem& network_pkey) override
    {
      CCF_ASSERT_FMT(
        self == INVALID_ID,
        "Calling initialize more than once, previous id:{}, new id:{}",
        self,
        self_id);
      self = self_id;
      channels =
        std::make_unique<ChannelManager>(writer_factory, network_pkey, self);
    }

    void create_channel(
      NodeId peer_id,
      const std::string& hostname,
      const std::string& service) override
    {
      if (peer_id == self)
      {
        return;
      }

      channels->create_channel(peer_id, hostname, service);
    }

    void destroy_channel(NodeId peer_id) override
    {
      if (peer_id == self)
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

    bool send_authenticated(
      const ccf::NodeMsgType& msg_type,
      NodeId to,
      const uint8_t* data,
      size_t size) override
    {
      auto n2n_channel = channels->get(to);
      return n2n_channel->send(msg_type, {data, size});
    }

    bool recv_authenticated(
      NodeId from_node, CBuffer cb, const uint8_t*& data, size_t& size) override
    {
      auto n2n_channel = channels->get(from_node);
      return n2n_channel->recv_authenticated(cb, data, size);
    }

    bool send_encrypted(
      const NodeMsgType& msg_type,
      CBuffer cb,
      NodeId to,
      const std::vector<uint8_t>& data) override
    {
      auto n2n_channel = channels->get(to);
      return n2n_channel->send(msg_type, cb, data);
    }

    bool recv_authenticated_with_load(
      NodeId from_node, const uint8_t*& data, size_t& size) override
    {
      auto n2n_channel = channels->get(from_node);
      return n2n_channel->recv_authenticated_with_load(data, size);
    }

    std::vector<uint8_t> recv_encrypted(
      NodeId from_node, CBuffer cb, const uint8_t* data, size_t size) override
    {
      auto n2n_channel = channels->get(from_node);

      auto plain = n2n_channel->recv_encrypted(cb, data, size);
      if (!plain.has_value())
      {
        throw std::logic_error(fmt::format(
          "Invalid encrypted node2node message from node {}", from_node));
      }

      return plain.value();
    }

    void process_key_exchange(const uint8_t* data, size_t size)
    {
      // Called on channel target when a key exchange message is received from
      // the initiator
      const auto& ke = serialized::overlay<ChannelHeader>(data, size);

      auto n2n_channel = channels->get(ke.from_node);
      n2n_channel->load_peer_signed_public(false, data, size);
    }

    void complete_key_exchange(const uint8_t* data, size_t size)
    {
      // Called on channel initiator when a key exchange response message is
      // received from the target
      const auto& ke = serialized::overlay<ChannelHeader>(data, size);

      auto n2n_channel = channels->get(ke.from_node);
      n2n_channel->load_peer_signed_public(true, data, size);
    }

    void recv_message(OArray&& oa) override
    {
      const uint8_t* data = oa.data();
      size_t size = oa.size();
      switch (serialized::peek<ChannelMsg>(data, size))
      {
        case key_exchange:
        {
          process_key_exchange(data, size);
          break;
        }

        case key_exchange_response:
        {
          complete_key_exchange(data, size);
          break;
        }

        default:
        {
        }
        break;
      }
    }
  };
}
