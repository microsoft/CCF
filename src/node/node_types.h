// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/frame_format.h"
#include "ccf/tx_id.h"
#include "ds/ring_buffer_types.h"

#include <cstdint>
#include <limits>

namespace ccf
{
  using Node2NodeMsg = uint64_t;

  // Type of messages exchanged between nodes
  enum NodeMsgType : Node2NodeMsg
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
    forwarded_cmd_v1 = 0,
    forwarded_response_v1,

    // Includes a command_id, so that forwarded requests and responses can be
    // precisely correlated. Supported since 2.0.8, emitted since 3.0.0
    forwarded_cmd_v2,
    forwarded_response_v2,

    // Includes session consistency information:
    // - cmd contains view in which all session requests must execute
    // - response contains bool indicating that session should be closed
    forwarded_cmd_v3,
    forwarded_response_v3
  };

#pragma pack(push, 1)
  // Channel-specific header for key exchange
  struct ChannelHeader
  {
    ChannelMsg msg;
    NodeId from_node;
  };

  // Frontend-specific header for forwarding
  struct ForwardedHeader_v1
  {
    ForwardedMsg msg;
    ccf::FrameFormat frame_format = ccf::FrameFormat::http;
  };

  struct ForwardedHeader_v2 : public ForwardedHeader_v1
  {
    using ForwardedCommandId = size_t;
    ForwardedCommandId id;
  };

  struct ForwardedCommandHeader_v3 : public ForwardedHeader_v2
  {
    ForwardedCommandHeader_v3() = default;
    ForwardedCommandHeader_v3(
      ForwardedHeader_v2::ForwardedCommandId cmd_id, ccf::View view)
    {
      ForwardedHeader_v1::msg = ForwardedMsg::forwarded_cmd_v3;
      ForwardedHeader_v2::id = cmd_id;
      active_view = view;
    }

    // The view in which this session is being executed. For consistency, we
    // pessimistically close this session if the node is in any other view.
    ccf::View active_view;
  };

  struct ForwardedResponseHeader_v3 : public ForwardedHeader_v2
  {
    ForwardedResponseHeader_v3() = default;
    ForwardedResponseHeader_v3(
      ForwardedHeader_v2::ForwardedCommandId cmd_id, bool terminate)
    {
      ForwardedHeader_v1::msg = ForwardedMsg::forwarded_response_v3;
      ForwardedHeader_v2::id = cmd_id;
      terminate_session = terminate;
    }

    // If the response contains a fatal error, indicate to the original node
    // that the session should be terminated.
    bool terminate_session;
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
  serializer::ByteRange);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::node_outbound,
  ccf::NodeId::Value,
  ccf::NodeMsgType,
  ccf::NodeId::Value,
  serializer::ByteRange);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::close_node_outbound, ccf::NodeId::Value);
