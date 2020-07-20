// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "channels.h"
#include "ds/serialized.h"
#include "enclave/rpc_handler.h"
#include "nodetypes.h"

#include <algorithm>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf
{
  class NodeToNode
  {
  private:
    NodeId self;
    std::unique_ptr<ChannelManager> channels;
    ringbuffer::AbstractWriterFactory& writer_factory;

  public:
    NodeToNode(ringbuffer::AbstractWriterFactory& writer_factory_) :
      writer_factory(writer_factory_)
    {}

    void initialize(NodeId self_id, const tls::Pem& network_pkey)
    {
      self = self_id;
      channels =
        std::make_unique<ChannelManager>(writer_factory, network_pkey, self);
    }

    void create_channel(
      NodeId peer_id, const std::string& hostname, const std::string& service)
    {
      if (peer_id == self)
      {
        return;
      }

      channels->create_channel(peer_id, hostname, service);
    }

    void destroy_channel(NodeId peer_id)
    {
      if (peer_id == self)
      {
        return;
      }

      channels->destroy_channel(peer_id);
    }

    void close_all_outgoing()
    {
      channels->close_all_outgoing();
    }

    template <class T>
    bool send_authenticated(
      const NodeMsgType& msg_type, NodeId to, const T& data)
    {
      auto& n2n_channel = channels->get(to);
      return n2n_channel.send(msg_type, asCb(data));
    }

    template <>
    bool send_authenticated(
      const NodeMsgType& msg_type, NodeId to, const std::vector<uint8_t>& data)
    {
      auto& n2n_channel = channels->get(to);
      return n2n_channel.send(msg_type, data);
    }

    template <class T>
    bool send_encrypted(
      const NodeMsgType& msg_type,
      NodeId to,
      const std::vector<uint8_t>& data,
      const T& msg_hdr)
    {
      auto& n2n_channel = channels->get(to);
      return n2n_channel.send(msg_type, asCb(msg_hdr), data);
    }

    template <class T>
    const T& recv_authenticated(const uint8_t*& data, size_t& size)
    {
      auto& t = serialized::overlay<T>(data, size);
      auto& n2n_channel = channels->get(t.from_node);

      if (!n2n_channel.recv_authenticated(asCb(t), data, size))
      {
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message from node {}", t.from_node));
      }

      return t;
    }

    template <class T>
    const T& recv_authenticated_with_load(const uint8_t*& data, size_t& size)
    {
      // PBFT only
      const auto* data_ = data;
      auto size_ = size;

      const auto& t = serialized::overlay<T>(data_, size_);
      auto& n2n_channel = channels->get(t.from_node);

      if (!n2n_channel.recv_authenticated_with_load(data, size))
      {
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message with load from node {}",
          t.from_node));
      }
      serialized::skip(data, size, sizeof(T));

      return t;
    }

    template <class T>
    std::pair<T, std::vector<uint8_t>> recv_encrypted(
      const uint8_t* data, size_t size)
    {
      auto t = serialized::read<T>(data, size);
      auto& n2n_channel = channels->get(t.from_node);

      auto plain = n2n_channel.recv_encrypted(asCb(t), data, size);
      if (!plain.has_value())
      {
        throw std::logic_error(fmt::format(
          "Invalid encrypted node2node message from node {}", t.from_node));
      }

      return std::make_pair(t, plain.value());
    }

    template <class T>
    RecvNonce get_recv_nonce(const uint8_t* data, size_t size)
    {
      // PBFT only
      serialized::read<T>(data, size);
      serialized::skip(data, size, (size - sizeof(GcmHdr)));
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      return ccf::get_nonce(hdr);
    }

    template <class T>
    RecvNonce get_encrypted_recv_nonce(const uint8_t* data, size_t size)
    {
      // PBFT only
      serialized::read<T>(data, size);
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      return ccf::get_nonce(hdr);
    }

    void process_key_exchange(const uint8_t* data, size_t size)
    {
      // Called on channel target when a key exchange message is received from
      // the initiator
      const auto& ke = serialized::overlay<ChannelHeader>(data, size);

      auto& n2n_channel = channels->get(ke.from_node);
      n2n_channel.load_peer_signed_public(false, data, size);
    }

    void complete_key_exchange(const uint8_t* data, size_t size)
    {
      // Called on channel initiator when a key exchange response message is
      // received from the target
      const auto& ke = serialized::overlay<ChannelHeader>(data, size);

      auto& n2n_channel = channels->get(ke.from_node);
      n2n_channel.load_peer_signed_public(true, data, size);
    }

    void recv_message(OArray&& oa)
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
        {}
        break;
      }
    }
  };
}
