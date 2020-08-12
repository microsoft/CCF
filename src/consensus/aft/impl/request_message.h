// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "consensus/aft/aft_types.h"

#include <vector>
#include <memory>

namespace aft
{
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

  private:
      std::vector<uint8_t> request;
      kv::TxHistory::RequestID rid;
      std::unique_ptr<RequestCtx> ctx;
      ReplyCallback cb;
  };
}