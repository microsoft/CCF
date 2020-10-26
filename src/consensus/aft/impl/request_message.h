// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "message.h"

#include <memory>
#include <vector>

namespace aft
{
// Request messages have the following format.
#pragma pack(push)
#pragma pack(1)
  struct RequestMessageRep : public consensus::ConsensusHeader<RaftMsgType>
  {
    RequestMessageRep() = default;
    RequestMessageRep(
      aft::NodeId from_node,
      uint16_t command_size_,
      uint16_t session_id_,
      kv::TxHistory::RequestID rid_) :
      consensus::ConsensusHeader<RaftMsgType>(
        RaftMsgType::bft_request, from_node),
      command_size(command_size_),
      session_id(session_id_),
      rid(rid_)
    {}

    uint16_t command_size;
    uint16_t session_id; // unique id of client who sends the request
    kv::TxHistory::RequestID rid; // unique request identifier
  };
#pragma pack(pop)

  class RequestMessage : public AbstractMessage
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
    {}

    bool should_encrypt() const override
    {
      return true;
    }

    RequestCtx& get_request_ctx() const
    {
      return *ctx;
    }

    void callback(std::vector<uint8_t>&& data)
    {
      if (cb != nullptr)
      {
        cb(nullptr, rid, 0, std::move(data));
      }
    }

    void serialize_message(
      aft::NodeId from_node, uint8_t* data, size_t size) const override
    {
      RequestMessageRep rep(from_node, request.size(), 0, rid);

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
      std::vector<uint8_t> request =
        serialized::read(data, size, rep.command_size);
      return std::make_unique<RequestMessage>(
        std::move(request), rep.rid, std::move(ctx), std::move(cb));
    }

    static std::unique_ptr<RequestMessage> deserialize(
      std::vector<uint8_t> request,
      kv::TxHistory::RequestID rid,
      std::unique_ptr<RequestCtx> ctx,
      ReplyCallback cb)
    {
      return std::make_unique<RequestMessage>(
        std::move(request), rid, std::move(ctx), std::move(cb));
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