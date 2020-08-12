// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "consensus/aft/aft_types.h"
#include "ds/serialized.h"

#include <vector>
#include <memory>

namespace aft
{

// Request messages have the following format.
#pragma pack(push)
#pragma pack(1)
  struct RequestMessageRep
  {
    short command_size;
    short cid; // unique id of client who sends the request
    kv::TxHistory::RequestID rid; // unique request identifier
    // Followed a command which is "command_size" bytes long and an
    // authenticator.
  };
#pragma pack(pop)
  class RequestMessage
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

    RequestCtx& get_request_ctx() const
    {
      return *ctx;
    }

    void callback(std::vector<uint8_t>& data)
    {
      cb(nullptr, rid, 0, data);
    }

    std::vector<uint8_t> serialize_request_message() const
    {
      std::vector<uint8_t> msg(sizeof(RequestMessageRep) + request.size());

      auto data_ = msg.data();
      auto size_ = msg.size();

      RequestMessageRep rep;
      rep.command_size = request.size();
      rep.cid = 0; // This is temporary and will make everything go via the primary
      rep.rid = rid;

      serialized::write(
        data_,
        size_,
        reinterpret_cast<uint8_t*>(&rep),
        sizeof(RequestMessageRep));
      serialized::write(data_, size_, request.data(), request.size());
      CCF_ASSERT(size_ == 0, "allocated buffer too large");

      return msg;
    }

  private:
    std::vector<uint8_t> request;
    kv::TxHistory::RequestID rid;
    std::unique_ptr<RequestCtx> ctx;
    ReplyCallback cb;
  };
}