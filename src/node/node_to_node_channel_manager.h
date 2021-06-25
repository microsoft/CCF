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

    void process_key_exchange_init(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      LOG_DEBUG_FMT("key_exchange_init from {}", from);

      // In the case of concurrent key_exchange_init's from both nodes, the one
      // with the lower ID wins.

      auto n2n_channel = get(from);
      if (n2n_channel)
        n2n_channel->consume_initiator_key_share(
          data, size, this_node->node_id < from);
    }

    void process_key_exchange_response(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      LOG_DEBUG_FMT("key_exchange_response from {}", from);
      auto n2n_channel = get(from);
      if (n2n_channel)
        n2n_channel->consume_responder_key_share(data, size);
    }

    void process_key_exchange_final(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      LOG_DEBUG_FMT("key_exchange_final from {}", from);
      auto n2n_channel = get(from);
      if (
        n2n_channel && !n2n_channel->check_peer_key_share_signature(data, size))
      {
        n2n_channel->reset();
      }
    }

  public:
    NodeToNodeChannelManager(
      ringbuffer::AbstractWriterFactory& writer_factory_) :
      writer_factory(writer_factory_)
    {}

    // TODO: Feels like this should be private
    std::shared_ptr<Channel> get(const NodeId& peer_id)
    {
      std::lock_guard<std::mutex> guard(lock);
      auto search = channels.find(peer_id);
      if (search != channels.end())
      {
        return search->second;
      }

      // Creating temporary channel that is not outgoing (at least for now)
      channels.try_emplace(
        peer_id,
        std::make_shared<Channel>(
          writer_factory,
          this_node->network_cert,
          this_node->node_kp,
          this_node->node_cert,
          this_node->node_id,
          peer_id));
      return channels.at(peer_id);
    }

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

    void create_channel(
      const NodeId& peer_id,
      const std::string& hostname,
      const std::string& service,
      std::optional<size_t> message_limit = std::nullopt) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling create_channel before channel manager is initialized");

      if (peer_id == this_node->node_id)
      {
        return;
      }

      if (!message_limit.has_value())
      {
        message_limit = Channel::default_message_limit;
      }

      std::lock_guard<std::mutex> guard(lock);

      auto search = channels.find(peer_id);
      if (search == channels.end())
      {
        LOG_DEBUG_FMT(
          "Creating new outbound channel to {} ({}:{})",
          peer_id,
          hostname,
          service);
        auto channel = std::make_shared<Channel>(
          writer_factory,
          this_node->network_cert,
          this_node->node_kp,
          this_node->node_cert,
          this_node->node_id,
          peer_id,
          hostname,
          service,
          *message_limit);
        channels.emplace_hint(search, peer_id, std::move(channel));
      }
      else if (!search->second)
      {
        LOG_INFO_FMT(
          "Re-creating new outbound channel to {} ({}:{})",
          peer_id,
          hostname,
          service);
        search->second = std::make_shared<Channel>(
          writer_factory,
          this_node->network_cert,
          this_node->node_kp,
          this_node->node_cert,
          this_node->node_id,
          peer_id,
          hostname,
          service,
          *message_limit);
      }
    }

    void destroy_channel(const NodeId& peer_id) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling destroy_channel before channel manager is initialized");

      if (peer_id == this_node->node_id)
      {
        return;
      }

      std::lock_guard<std::mutex> guard(lock);
      auto search = channels.find(peer_id);
      if (search == channels.end())
      {
        LOG_FAIL_FMT(
          "Cannot destroy node channel with {}: channel does not exist",
          peer_id);
        return;
      }

      search->second = nullptr;
    }

    void destroy_all_channels() override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling destroy_all_channels before channel manager is initialized");

      std::lock_guard<std::mutex> guard(lock);
      channels.clear();
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

      auto n2n_channel = get(to);
      return n2n_channel->send(type, {data, size});
    }

    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      CBuffer cb,
      const std::vector<uint8_t>& data) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling send_encrypted (to {}) before channel manager is initialized",
        to);

      auto n2n_channel = get(to);
      return n2n_channel ? n2n_channel->send(type, cb, data) : true;
    }

    bool recv_authenticated(
      const NodeId& from,
      CBuffer cb,
      const uint8_t*& data,
      size_t& size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_authenticated (from {}) before channel manager is "
        "initialized",
        from);

      auto n2n_channel = get(from);
      // Receiving after a channel has been destroyed is ok.
      return n2n_channel ? n2n_channel->recv_authenticated(cb, data, size) :
                           true;
    }

    bool recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_authenticated_with_load (from {}) before channel manager "
        "is "
        "initialized",
        from);

      auto n2n_channel = get(from);
      return n2n_channel ?
        n2n_channel->recv_authenticated_with_load(data, size) :
        true;
    }

    std::vector<uint8_t> recv_encrypted(
      const NodeId& from, CBuffer cb, const uint8_t* data, size_t size) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_encrypted (from {}) before channel manager is "
        "initialized",
        from);

      auto n2n_channel = get(from);

      if (!n2n_channel)
        return {};

      auto plain = n2n_channel->recv_encrypted(cb, data, size);
      if (!plain.has_value())
      {
        throw DroppedMessageException(from);
      }

      return plain.value();
    }

    void recv_message(const NodeId& from, OArray&& oa) override
    {
      CCF_ASSERT_FMT(
        this_node != nullptr,
        "Calling recv_message (from {}) before channel manager is "
        "initialized",
        from);

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
