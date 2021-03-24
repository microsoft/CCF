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
      const NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service) = 0;

    virtual void destroy_channel(const NodeId& peer_id) = 0;

    virtual void close_all_outgoing() = 0;

    virtual void destroy_all_channels() = 0;

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
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message from node {}", from));
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
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message with load from node {}",
          from));
      }
      serialized::skip(data, size, sizeof(T));

      return t;
    }

    virtual bool recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size) = 0;

    virtual bool recv_authenticated(
      const NodeId& from, CBuffer cb, const uint8_t*& data, size_t& size) = 0;

    virtual void recv_message(const NodeId& from, OArray&& oa) = 0;

    virtual void initialize(
      const NodeId& self_id, const crypto::Pem& network_pkey) = 0;

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
      const NodeId& self_id, const crypto::Pem& network_pkey) override
    {
      CCF_ASSERT_FMT(
        !self.has_value(),
        "Calling initialize more than once, previous id:{}, new id:{}",
        self.value(),
        self_id);

      self = self_id;
      channels = std::make_unique<ChannelManager>(
        writer_factory, network_pkey, self.value());
    }

    void create_channel(
      const NodeId& peer_id,
      const std::string& hostname,
      const std::string& service) override
    {
      if (peer_id == self.value())
      {
        return;
      }

      channels->create_channel(peer_id, hostname, service);
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
      return n2n_channel->recv_authenticated(cb, data, size);
    }

    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      CBuffer cb,
      const std::vector<uint8_t>& data) override
    {
      auto n2n_channel = channels->get(to);
      return n2n_channel->send(type, cb, data);
    }

    bool recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size) override
    {
      auto n2n_channel = channels->get(from);
      return n2n_channel->recv_authenticated_with_load(data, size);
    }

    std::vector<uint8_t> recv_encrypted(
      const NodeId& from, CBuffer cb, const uint8_t* data, size_t size) override
    {
      auto n2n_channel = channels->get(from);

      auto plain = n2n_channel->recv_encrypted(cb, data, size);
      if (!plain.has_value())
      {
        throw std::logic_error(fmt::format(
          "Invalid encrypted node2node message from node {}", from));
      }

      return plain.value();
    }

    void process_key_exchange(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      // Called on channel target when a key exchange message is received from
      // the initiator
      auto n2n_channel = channels->get(from);
      n2n_channel->load_peer_signed_public(false, data, size);
    }

    void complete_key_exchange(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      // Called on channel initiator when a key exchange response message is
      // received from the target
      auto n2n_channel = channels->get(from);
      n2n_channel->load_peer_signed_public(true, data, size);
    }

    void recv_message(const NodeId& from, OArray&& oa) override
    {
      try
      {
        const uint8_t* data = oa.data();
        size_t size = oa.size();
        switch (serialized::read<ChannelMsg>(data, size))
        {
          case key_exchange:
          {
            process_key_exchange(from, data, size);
            break;
          }

          case key_exchange_response:
          {
            complete_key_exchange(from, data, size);
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
