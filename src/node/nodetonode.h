// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "channels.h"
#include "ds/serialized.h"
#include "nodetypes.h"

#include <algorithm>

namespace ccf
{
  class NodeToNode
  {
  private:
    NodeId self;
    std::unique_ptr<ChannelManager> channels;
    std::unique_ptr<ringbuffer::AbstractWriter> to_host;

    void established_channel(NodeId to)
    {
      // If the channel is not yet established, replace all sent messages with
      // a key exchange message. In the case of raft, this is acceptable since
      // append entries and vote requests are re-sent after a short timeout
      auto signed_public = channels->get_signed_public(to);
      if (!signed_public.has_value())
        return;

      LOG_DEBUG << "node2node channel with " << to << " initiated" << std::endl;

      ChannelHeader msg = {ChannelMsg::key_exchange, self};
      to_host->write(
        node_outbound,
        to,
        NodeMsgType::channel_msg,
        msg,
        signed_public.value());
    }

  public:
    NodeToNode(ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside())
    {}

    void initialize(NodeId id, const std::vector<uint8_t>& network_pkey)
    {
      self = id;
      channels = std::make_unique<ChannelManager>(network_pkey);
    }

    template <class T>
    void send_authenticated(NodeId to, const T& data)
    {
      auto& n2n_channel = channels->get(to);
      if (n2n_channel.get_status() != ChannelStatus::ESTABLISHED)
      {
        established_channel(to);
        return;
      }

      // The secure channel between self and to has already been established
      GcmHdr hdr;
      n2n_channel.tag(hdr, asCb(data));
      to_host->write(node_outbound, to, NodeMsgType::consensus_msg, data, hdr);
    }

    template <class T>
    const T& recv_authenticated(const uint8_t*& data, size_t& size)
    {
      const auto& t = serialized::overlay<T>(data, size);
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);

      auto& n2n_channel = channels->get(t.from_node);

      if (!n2n_channel.verify(hdr, asCb(t)))
        throw std::logic_error("Invalid node2node message");

      return t;
    }

    bool forward(
      NodeId to, CallerId caller_id, const std::vector<uint8_t>& data)
    {
      auto& n2n_channel = channels->get(to);
      if (n2n_channel.get_status() != ChannelStatus::ESTABLISHED)
      {
        established_channel(to);
        return false;
      }

      std::vector<uint8_t> plain(sizeof(caller_id) + data.size());
      std::vector<uint8_t> cipher(plain.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, data.data(), data.size());

      GcmHdr hdr;
      ChannelHeader msg = {ChannelMsg::encrypted_msg, self};
      n2n_channel.encrypt(hdr, asCb(msg), plain, cipher);

      to_host->write(
        node_outbound, to, NodeMsgType::forwarded_msg, msg, hdr, cipher);

      return true;
    }

    std::pair<CallerId, std::vector<uint8_t>> recv_forwarded(
      const uint8_t* data, size_t size)
    {
      const auto& msg = serialized::overlay<ccf::Header>(data, size);
      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      std::vector<uint8_t> plain(size);

      auto& n2n_channel = channels->get(msg.from_node);
      if (!n2n_channel.decrypt(hdr, asCb(msg), {data, size}, plain))
        throw std::logic_error("Invalid node2node message");

      const auto& plain_ = plain;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto caller_id = serialized::read<CallerId>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return {caller_id, rpc};
    }

    void process_key_exchange(const uint8_t* data, size_t size)
    {
      // Called on channel target when a key exchange message is received from
      // the initiator
      const auto& ke = serialized::overlay<ChannelHeader>(data, size);

      auto signed_public = channels->get_signed_public(ke.from_node);
      if (!signed_public.has_value())
        return;

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

    void recv_message(const uint8_t* data, size_t size)
    {
      switch (serialized::peek<ChannelMsg>(data, size))
      {
        case key_exchange:
          process_key_exchange(data, size);
          break;

        case key_exchange_response:
          complete_key_exchange(data, size);
          break;

        default:
        {}
        break;
      }
    }
  };
}
