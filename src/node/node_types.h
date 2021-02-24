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
    key_exchange = 0,
    key_exchange_response,
    encrypted_msg
  };

  // Types of frontend messages
  enum ForwardedMsg : Node2NodeMsg
  {
    forwarded_cmd = 0,
    forwarded_response,
    request_hash
  };

#pragma pack(push, 1)
  // Header for every message exchange between nodes
  struct Header
  {
    Node2NodeMsg msg;
    NodeId from_node; // TODO: Make this an array
  };

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
    NodeId from_node;
    enclave::FrameFormat frame_format = enclave::FrameFormat::http;
  };

  struct MessageHash
  {
    MessageHash() = default;
    MessageHash(ForwardedMsg msg_, NodeId from_node_) :
      msg(msg_),
      from_node(from_node_)
    {}

    ForwardedMsg msg;
    NodeId from_node;
    crypto::Sha256Hash hash;
  };
#pragma pack(pop)

  /// Node-to-node related ringbuffer messages
  enum : ringbuffer::Message
  {
    ///@{
    /// Change the network nodes. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(add_node),
    DEFINE_RINGBUFFER_MSG_TYPE(remove_node),
    ///@}

    /// Receive data from another node. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(node_inbound),

    /// Send data to another node. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(node_outbound),
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::add_node, ccf::NodeId, std::string, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(ccf::remove_node, ccf::NodeId);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(ccf::node_inbound, std::vector<uint8_t>);