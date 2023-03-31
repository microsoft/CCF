// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/locking.h"
#include "channels.h"
#include "node/node_to_node.h"

namespace ccf
{
  class NodeToNodeChannelManager : public NodeToNode
  {
  private:
    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host;

    std::unordered_map<NodeId, std::shared_ptr<Channel>> channels;
    ccf::pal::Mutex lock; //< Protects access to channels map

    struct ThisNode
    {
      NodeId node_id;
      crypto::Pem service_cert;
      crypto::KeyPairPtr node_kp;
      std::optional<crypto::Pem> endorsed_node_cert = std::nullopt;
    };
    std::unique_ptr<ThisNode> this_node; //< Not available at construction, only
                                         // after calling initialize()

    // This is set during node startup, using a value from the run-time
    // configuration (unless a unit test has set a compile-time default)
    std::optional<size_t> message_limit =
#ifdef OVERRIDE_DEFAULT_N2N_MESSAGE_LIMIT
      OVERRIDE_DEFAULT_N2N_MESSAGE_LIMIT;
#else
      std::nullopt;
#endif

    std::shared_ptr<Channel> get_channel(const NodeId& peer_id)
    {
      CCF_ASSERT_FMT(
        this_node == nullptr || this_node->node_id != peer_id,
        "Requested channel with self {}",
        peer_id);

      CCF_ASSERT_FMT(
        message_limit.has_value(),
        "Node-to-node message limit has not yet been set");

      std::lock_guard<ccf::pal::Mutex> guard(lock);
      CCF_ASSERT_FMT(
        this_node != nullptr && this_node->endorsed_node_cert.has_value(),
        "Endorsed node certificate has not yet been set");

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
          this_node->service_cert,
          this_node->node_kp,
          this_node->endorsed_node_cert.value(),
          this_node->node_id,
          peer_id,
          message_limit.value()));
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
      const crypto::Pem& service_cert,
      crypto::KeyPairPtr node_kp,
      const std::optional<crypto::Pem>& node_cert) override
    {
      CCF_ASSERT_FMT(
        this_node == nullptr,
        "Calling initialize more than once, previous id:{}, new id:{}",
        this_node->node_id,
        self_id);

      if (
        node_cert.has_value() &&
        make_verifier(node_cert.value())->is_self_signed())
      {
        LOG_INFO_FMT(
          "Refusing to initialize node-to-node channels with "
          "self-signed node certificate.");
        return;
      }

      this_node = std::unique_ptr<ThisNode>(
        new ThisNode{self_id, service_cert, node_kp, node_cert});
    }

    void set_endorsed_node_cert(const crypto::Pem& endorsed_node_cert) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      this_node->endorsed_node_cert = endorsed_node_cert;
    }

    void set_message_limit(size_t message_limit_) override
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

    bool have_channel(const ccf::NodeId& nid) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      return channels.find(nid) != channels.end();
    }

    bool channel_open(const NodeId& peer_id)
    {
      return get_channel(peer_id)->channel_open();
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

      return get_channel(to)->send(type, std::span<const uint8_t>(data, size));
    }

    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      std::span<const uint8_t> header,
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
      std::span<const uint8_t> header,
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
      std::span<const uint8_t> header,
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
    bool recv_channel_message(const NodeId& from, std::vector<uint8_t>&& body)
    {
      return recv_channel_message(from, body.data(), body.size());
    }
  };
}
