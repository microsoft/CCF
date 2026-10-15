// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"

#include <cstdint>

namespace ccf
{
  using Node2NodeMsg = uint64_t;

  // NOLINTBEGIN(performance-enum-size)

  // Type of messages exchanged between nodes
  enum NodeMsgType : Node2NodeMsg
  {
    channel_msg = 0,
    consensus_msg
  };
  // NB: The node-to-node channels assume only 2 types of messages exist, and
  // treat them differently. Adding a new message type will likely need
  // additional changes.

  // Types of channel messages
  enum ChannelMsg : Node2NodeMsg
  {
    key_exchange_init = 0,
    key_exchange_response,
    key_exchange_final
  };

  // NOLINTEND(performance-enum-size)

#pragma pack(push, 1)
  // Channel-specific header for key exchange
  struct ChannelHeader
  {
    ChannelMsg msg;
    NodeId from_node;
  };

#pragma pack(pop)
}
