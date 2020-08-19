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
  struct OpenNetworkMessageRep : public MessageRep
  {
    OpenNetworkMessageRep() : MessageRep(MessageTag::OpenNetwork) {}
  };
#pragma pack(pop)

  class OpenNetworkMessage : public IMessage
  {
  public:
    bool should_encrypt() const override
    {
      return false;
    }

    void serialize_message(uint8_t* data, size_t size) const override
    {
      OpenNetworkMessageRep rep;

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

  class OpenNetworkMessageRecv
  {
  public:
    OpenNetworkMessageRecv(OArray&& oa_, kv::NodeId from_) :
      oa(std::move(oa_)),
      from(from_)
    {}

  private:
    OArray oa;
    kv::NodeId from;
  };

#pragma pack(push)
#pragma pack(1)
  struct OpenNetworkMessageRespRep : public MessageRep
  {
    OpenNetworkMessageRespRep() : MessageRep(MessageTag::OpenNetworkResp) {}
  };
#pragma pack(pop)

  class OpenNetworkMessageResp : public IMessage
  {
  public:
    bool should_encrypt() const override
    {
      return false;
    }

    void serialize_message(uint8_t* data, size_t size) const override
    {
      OpenNetworkMessageRespRep rep;

      serialized::write(
        data,
        size,
        reinterpret_cast<uint8_t*>(&rep),
        sizeof(OpenNetworkMessageRespRep));
    }
    size_t size() const override
    {
      return sizeof(OpenNetworkMessageRespRep);
    }
  };

  class OpenNetworkMessageRespRecv
  {
  public:
    OpenNetworkMessageRespRecv(OArray&& oa_, kv::NodeId from_) :
      oa(std::move(oa_)),
      from(from_)
    {}

  private:
    OArray oa;
    kv::NodeId from;
  };
}