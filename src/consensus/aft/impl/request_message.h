// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "consensus/aft/aft_types.h"
#include "ds/serialized.h"
#include "message.h"

#include <vector>
#include <memory>

namespace aft
{

// Request messages have the following format.
#pragma pack(push)
#pragma pack(1)
  struct RequestMessageRep : public MessageRep
  {
    RequestMessageRep() = default;
    RequestMessageRep(
      short command_size_, short cid_, kv::TxHistory::RequestID rid_) :
      MessageRep(MessageTag::Request),
      command_size(command_size_),
      cid(cid_),
      rid(rid_)
    {}

    short command_size;
    short cid; // unique id of client who sends the request
    kv::TxHistory::RequestID rid; // unique request identifier
  };
#pragma pack(pop)

  class RequestMessage : public IMessage
  {
  public:
    RequestMessage(
      std::vector<uint8_t> request_,
      kv::TxHistory::RequestID rid_,
      std::unique_ptr<RequestCtx> ctx_,
      ReplyCallback cb_) :
      request(std::move(request_)),
      rid(rid_),
      ctx(std::move(ctx_)),
      cb(std::move(cb_))
    {

    }

    bool should_encrypt() const override
    {
      return true;
    }

    RequestCtx& get_request_ctx() const
    {
      return *ctx;
    }

    void callback(std::vector<uint8_t>& data)
    {
      if (cb != nullptr)
      {
        cb(nullptr, rid, 0, data);
      }
    }

    void serialize_message(uint8_t* data, size_t size) const override
    {
      RequestMessageRep rep(
        request.size(),
        0, // This is temporary and will make everything go via the primary
        rid);

      serialized::write(
        data,
        size,
        reinterpret_cast<uint8_t*>(&rep),
        sizeof(RequestMessageRep));
      serialized::write(data, size, request.data(), request.size());
      CCF_ASSERT(size == 0, "allocated buffer is too large");
    }

    static std::unique_ptr<RequestMessage> deserialize(
      const uint8_t* data,
      size_t size,
      std::unique_ptr<RequestCtx> ctx,
      ReplyCallback cb)
    {
      auto rep = serialized::read<RequestMessageRep>(data, size);
      std::vector<uint8_t> request = serialized::read(data, size, rep.command_size);
      return std::make_unique<RequestMessage>(std::move(request), rep.rid, std::move(ctx), std::move(cb));
    }

    size_t size() const override
    {
      return sizeof(RequestMessageRep) + request.size();
    }

  private:
    std::vector<uint8_t> request;
    kv::TxHistory::RequestID rid;
    std::unique_ptr<RequestCtx> ctx;
    ReplyCallback cb;
  };
}