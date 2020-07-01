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
    ringbuffer::WriterPtr to_host;
    ringbuffer::AbstractWriterFactory& writer_factory;

    bool try_establish_channel(NodeId peer_id, Channel& channel)
    {
      if (channel.get_status() != ChannelStatus::ESTABLISHED)
      {
        // If the channel is not yet established, replace all sent messages with
        // a key exchange message. In the case of raft, this is acceptable since
        // append entries and vote requests are re-sent after a short timeout
        // https://github.com/microsoft/CCF/issues/1015
        auto signed_public = channels->get_signed_public(peer_id);
        if (!signed_public.has_value())
        {
          return false;
        }

        ChannelHeader msg = {ChannelMsg::key_exchange, self};
        to_host->write(
          node_outbound,
          peer_id,
          NodeMsgType::channel_msg,
          msg,
          signed_public.value());

        LOG_DEBUG_FMT("node2node channel with {} initiated", peer_id);
        return false;
      }

      return true;
    }

  public:
    NodeToNode(ringbuffer::AbstractWriterFactory& writer_factory_) :
      writer_factory(writer_factory_),
      to_host(writer_factory_.create_writer_to_outside())
    {}

    void initialize(NodeId self_id, const tls::Pem& network_pkey)
    {
      self = self_id;
      channels = std::make_unique<ChannelManager>(writer_factory, network_pkey);
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
      if (!n2n_channel.has_value())
      {
        LOG_FAIL_FMT(
          "Cannot send authenticated message to node {}: channel no longer "
          "exists",
          to);
        return false;
      }

      if (!try_establish_channel(to, n2n_channel.value()))
      {
        return false;
      }

      // The secure channel between self and to has already been established
      GcmHdr hdr;
      n2n_channel->tag(hdr, asCb(data));

      to_host->write(node_outbound, to, msg_type, data, hdr);
      return true;
    }

    template <>
    bool send_authenticated(
      const NodeMsgType& msg_type, NodeId to, const std::vector<uint8_t>& data)
    {
      auto& n2n_channel = channels->get(to);
      if (!n2n_channel.has_value())
      {
        LOG_FAIL_FMT(
          "Cannot send authenticated message to node {}: channel no longer "
          "exists",
          to);
        return false;
      }

      if (!try_establish_channel(to, n2n_channel.value()))
      {
        return false;
      }

      // The secure channel between self and to has already been established
      GcmHdr hdr;
      n2n_channel->tag(hdr, data);

      to_host->write(node_outbound, to, msg_type, data, hdr);
      return true;
    }

    template <class T>
    const T& recv_authenticated(const uint8_t*& data, size_t& size)
    {
      const auto& t = serialized::overlay<T>(data, size);
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);

      auto& n2n_channel = channels->get(t.from_node);
      if (!n2n_channel.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot recv authenticated message from node {}: channel no longer "
          "exists",
          t.from_node));
      }

      if (!n2n_channel->verify(hdr, asCb(t)))
      {
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message from node {} (size: {})",
          t.from_node,
          size));
      }

      return t;
    }

    template <class T>
    RecvNonce get_recv_nonce(const uint8_t* data, size_t size)
    {
      const auto& t = serialized::overlay<T>(data, size);
      serialized::skip(data, size, (size - sizeof(GcmHdr)));
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      return ccf::Channel::get_nonce(hdr);
    }

    template <class T>
    RecvNonce get_encrypted_recv_nonce(const uint8_t* data, size_t size)
    {
      const auto& t = serialized::overlay<T>(data, size);
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      return ccf::Channel::get_nonce(hdr);
    }

    template <class T>
    CBuffer recv_authenticated_with_load(const uint8_t*& data, size_t& size)
    {
      // data contains the message header of type T, the raw data, and the gcm
      // header at the end
      const auto* payload_data = data;
      auto payload_size = size - sizeof(GcmHdr);

      const auto& t = serialized::overlay<T>(data, size);
      serialized::skip(data, size, (size - sizeof(GcmHdr)));
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);

      auto& n2n_channel = channels->get(t.from_node);
      if (!n2n_channel.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot recv authenticated message from node {}: channel no longer "
          "exists",
          t.from_node));
      }

      if (!n2n_channel->verify(hdr, {payload_data, payload_size}))
      {
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message from node {} (size: {})",
          t.from_node,
          size));
      }

      serialized::skip(payload_data, payload_size, sizeof(T));
      return {payload_data, payload_size};
    }

    template <class T>
    bool send_encrypted(
      const NodeMsgType& msg_type,
      NodeId to,
      const std::vector<uint8_t>& data,
      const T& msg_hdr)
    {
      auto& n2n_channel = channels->get(to);
      if (!n2n_channel.has_value())
      {
        LOG_FAIL_FMT(
          "Cannot send encrypted message to node {}: channel no longer "
          "exists",
          to);
        return false;
      }

      if (!try_establish_channel(to, n2n_channel.value()))
      {
        return false;
      }

      GcmHdr hdr;
      std::vector<uint8_t> cipher(data.size());
      n2n_channel->encrypt(hdr, asCb(msg_hdr), data, cipher);

      to_host->write(node_outbound, to, msg_type, msg_hdr, hdr, cipher);

      return true;
    }

    template <class T>
    std::pair<T, std::vector<uint8_t>> recv_encrypted(
      const uint8_t* data, size_t size)
    {
      auto t = serialized::read<T>(data, size);
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      std::vector<uint8_t> plain(size);

      auto& n2n_channel = channels->get(t.from_node);
      if (!n2n_channel.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot recv encrypted message from node {}: channel no longer "
          "exists",
          t.from_node));
      }

      if (!n2n_channel->decrypt(hdr, asCb(t), {data, size}, plain))
      {
        throw std::logic_error(fmt::format(
          "Invalid authenticated node2node message from node {} (size: {})",
          t.from_node,
          size));
      }

      return std::make_pair(t, plain);
    }

    void process_key_exchange(const uint8_t* data, size_t size)
    {
      // Called on channel target when a key exchange message is received from
      // the initiator
      const auto& ke = serialized::overlay<ChannelHeader>(data, size);

      auto signed_public = channels->get_signed_public(ke.from_node);
      if (!signed_public.has_value())
      {
        // Channel is already established
        return;
      }

      if (!channels->load_peer_signed_public(
            ke.from_node, std::vector<uint8_t>(data, data + size)))
      {
        return;
      }

      ChannelHeader msg = {ChannelMsg::key_exchange_response, self};
      to_host->write(
        node_outbound,
        ke.from_node,
        NodeMsgType::channel_msg,
        msg,
        signed_public.value());
    }

    void complete_key_exchange(const uint8_t* data, size_t size)
    {
      // Called on channel initiator when a key exchange response message is
      // received from the target
      const auto& ke = serialized::overlay<ChannelHeader>(data, size);

      if (!channels->load_peer_signed_public(
            ke.from_node, std::vector<uint8_t>(data, data + size)))
      {
        return;
      }
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
