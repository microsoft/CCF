// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "kv/kv_types.h"
#include "message.h"

namespace aft
{
#pragma pack(push)
#pragma pack(1)
  struct RequestDataMessageRep : public MessageRep
  {
    RequestDataMessageRep(kv::Version from_, kv::Version to_) :
      MessageRep(MessageTag::RequestData), from(from_), to(to_)
    {}

    kv::Version from;
    kv::Version to;
  };
#pragma pack(pop)

  class RequestDataMessage : public IMessage
  {
  public:
    RequestDataMessage(kv::Version from_, kv::Version to_) : from(from_), to(to_) {}

    bool should_encrypt() const override
    {
      return false;
    }

    void serialize_message(uint8_t* data, size_t size) const override
    {
      RequestDataMessageRep rep(from, to);

      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&rep), sizeof(RequestDataMessageRep));
      CCF_ASSERT(size == 0, "allocated buffer is too large");

    }

    size_t size() const override
    {
      return sizeof(RequestDataMessage);
    }

  private:
    kv::Version from;
    kv::Version to;
  };

  class RequestDataMessageRecv
  {
  public:
    RequestDataMessageRecv(OArray&& oa_, kv::NodeId from_) :
      oa(std::move(oa_)), from(from_)
    {}

    kv::Version get_from()
    {
      return reinterpret_cast<const RequestDataMessageRep*>(oa.data())->from;
    }

    kv::Version get_to()
    {
      return reinterpret_cast<const RequestDataMessageRep*>(oa.data())->to;
    }

  private:
    OArray oa;
    kv::NodeId from;
  };
}