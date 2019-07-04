// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ringbuffer_types.h"

namespace pbft
{
  using Index = int64_t;
  using Term = uint64_t;
  using NodeId = uint64_t;
  using Node2NodeMsg = uint64_t;
  using CallerId = uint64_t;

  enum PbftMsgType : Node2NodeMsg
  {
    pbft_message = 0,
  };

#pragma pack(push, 1)
  struct PbftHeader
  {
    PbftMsgType msg;
    NodeId from_node;
  };
#pragma pack(pop)
}