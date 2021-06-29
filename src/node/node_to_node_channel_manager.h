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
    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host;

    std::unordered_map<NodeId, std::shared_ptr<Channel>> channels;
    std::mutex lock; //< Protects access to channels map

    struct ThisNode
    {
      NodeId node_id;
      const crypto::Pem& network_cert;
      crypto::KeyPairPtr node_kp;
      const crypto::Pem& node_cert;
    };
    std::unique_ptr<ThisNode> this_node; //< Not available at construction, only
                                         // after calling initialize()

    size_t message_limit = Channel::default_message_limit;

    std::shared_ptr<Channel> get_channel(const NodeId& peer_id)
    {
      CCF_ASSERT_FMT(
        this_node == nullptr || this_node->node_id != peer_id,
        "Requested channel with self {}",
        peer_id);

      std::lock_guard<std::mutex> guard(lock);

      auto search = channels.find(peer_id);
      if (search != channels.end())
      {
        return search->second;
      }

      // Create channel
      channels.try_emplace(
        peer_id,
        std::make_shared<Channel>(
          writer_factory,
          this_node->network_cert,
          this_node->node_kp,
          this_node->node_cert,
          this_node->node_id,
          peer_id,
          message_limit));
      return channels.at(peer_id);
    }

  public:
    NodeToNodeChannelManager(
      ringbuffer::AbstractWriterFactory& writer_factory_) :
      writer_factory(writer_factory_),
      to_host(writer_factory_.create_writer_to_outside())
    {}

    void initialize(
      const NodeId& self_id,
      const crypto::Pem& network_cert,
      crypto::KeyPairPtr node_kp,
      const crypto::Pem& node_cert) override
    {
      CCF_ASSERT_FMT(
        this_node == nullptr,
        "Calling initialize more than once, previous id:{}, new id:{}",
        this_node->node_id,
        self_id);

      if (make_verifier(node_cert)->is_self_signed())
      {
        LOG_INFO_FMT(
          "Refusing to initialize node-to-node channels with "
          "this_node->node_id-signed node "
          "certificate.");
        return;
      }

      this_node = std::unique_ptr<ThisNode>(
        new ThisNode{self_id, network_cert, node_kp, node_cert});
    }

    void set_message_limit(size_t message_limit_)
    {
      message_limit = message_limit_;
    }

    virtual void associate_node_address(
      const NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service) override
    {
      RINGBUFFER_WRITE_MESSAGE(
        ccf::associate_node_address,
        to_host,
        peer_id.value(),
        peer_hostname,
        peer_service);
    }

    void close_channel(const NodeId& peer_id) override
    {
      get_channel(peer_id)->close_channel();
    }

    ChannelStatus get_status(const NodeId& peer_id)
    {
      return get_channel(peer_id)->get_status();
    }

    bool send_authenticated(
      const NodeId& to,
      NodeMsgType type,
      const uint8_t* data,
      size_t size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling send_authenticated before channel manager is initialized");

      return get_channel(to)->send(type, {data, size});
    }

    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      CBuffer header,
      const std::vector<uint8_t>& data) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling send_encrypted (to {}) before channel manager is initialized",
        to);

      return get_channel(to)->send(type, header, data);
    }

    bool recv_authenticated(
      const NodeId& from,
      CBuffer header,
      const uint8_t*& data,
      size_t& size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_authenticated (from {}) before channel manager is "
        "initialized",
        from);

      return get_channel(from)->recv_authenticated(header, data, size);
    }

    bool recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_authenticated_with_load (from {}) before channel manager "
        "is initialized",
        from);

      return get_channel(from)->recv_authenticated_with_load(data, size);
    }

    std::vector<uint8_t> recv_encrypted(
      const NodeId& from,
      CBuffer header,
      const uint8_t* data,
      size_t size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_encrypted (from {}) before channel manager is "
        "initialized",
        from);

      auto plain = get_channel(from)->recv_encrypted(header, data, size);
      if (!plain.has_value())
      {
        throw DroppedMessageException(from);
      }

      return plain.value();
    }

    bool recv_channel_message(
      const NodeId& from, const uint8_t* data, size_t size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_message (from {}) before channel manager is "
        "initialized",
        from);

      return get_channel(from)->recv_key_exchange_message(data, size);
    }

    // NB: Only used by tests!
    bool recv_channel_message(
      const NodeId& from, std::vector<uint8_t>&& body)
    {
      return recv_channel_message(from, body.data(), body.size());
    }
  };
}
