// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "ds/ring_buffer_types.h"
#include "entities.h"

#include <cstdint>
#include <limits>

namespace ccf
{
  using Node2NodeMsg = uint64_t;

  // Type of messages exchanged between nodes
  enum NodeMsgType : uint64_t
  {
    channel_msg = 0,
    consensus_msg,
    forwarded_msg
  };

  // Types of channel messages
  enum ChannelMsg : Node2NodeMsg
  {
    key_exchange_init = 0,
    key_exchange_response,
    key_exchange_final
  };

  // Types of frontend messages
  enum ForwardedMsg : Node2NodeMsg
  {
    forwarded_cmd = 0,
    forwarded_response,
    request_hash
  };

#pragma pack(push, 1)
  // Channel-specific header for key exchange
  struct ChannelHeader
  {
    ChannelMsg msg;
    NodeId from_node;
  };

  // Frontend-specific header for forwarding
  struct ForwardedHeader
  {
    ForwardedMsg msg;
    enclave::FrameFormat frame_format = enclave::FrameFormat::http;
  };

  struct MessageHash
  {
    MessageHash() = default;
    MessageHash(ForwardedMsg msg_, crypto::Sha256Hash&& hash_) :
      msg(msg_),
      hash(std::move(hash_))
    {}

    ForwardedMsg msg;
    crypto::Sha256Hash hash;
  };
#pragma pack(pop)

  /// Node-to-node related ringbuffer messages
  enum : ringbuffer::Message
  {
    /// Change the network nodes. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(associate_node_address),

    /// Receive data from another node. Host -> Enclave
    /// Args are (msg_type, from_id, payload)
    DEFINE_RINGBUFFER_MSG_TYPE(node_inbound),

    /// Send data to another node. Enclave -> Host
    /// Args are (to_id, msg_type, from_id, payload)
    /// The host may inspect the first 3, and should write the last 3 (to
    /// produce an equivalent node_inbound on the receiving node)
    DEFINE_RINGBUFFER_MSG_TYPE(node_outbound),

    /// Close connection to another node. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(close_node_outbound)
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::associate_node_address, ccf::NodeId::Value, std::string, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::node_inbound,
  ccf::NodeMsgType,
  ccf::NodeId::Value,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::node_outbound,
  ccf::NodeId::Value,
  ccf::NodeMsgType,
  ccf::NodeId::Value,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::close_node_outbound, ccf::NodeId::Value); // TODO: implement this