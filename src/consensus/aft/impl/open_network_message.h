// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "message.h"

namespace aft
{
// Request messages have the following format.
#pragma pack(push)
#pragma pack(1)
  struct OpenNetworkMessageRep : public consensus::ConsensusHeader<RaftMsgType>
  {
    OpenNetworkMessageRep(aft::NodeId from_node) :
      consensus::ConsensusHeader<RaftMsgType>(bft_OpenNetwork, from_node)
    {}
  };
#pragma pack(pop)

  class OpenNetworkMessage : public IMessage
  {
  public:
    bool should_encrypt() const override
    {
      return false;
    }

    void serialize_message(aft::NodeId from_node, uint8_t* data, size_t size) const override
    {
      OpenNetworkMessageRep rep(from_node);

      serialized::write(
        data,
        size,
        reinterpret_cast<uint8_t*>(&rep),
        sizeof(OpenNetworkMessageRep));
    }
    size_t size() const override
    {
      return sizeof(OpenNetworkMessageRep);
    }
  };
} 