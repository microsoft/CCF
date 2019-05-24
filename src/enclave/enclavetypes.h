// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

// TODO: Remove this dependency
#include "node/rpc/jsonrpc.h"

#include "ds/buffer.h"

#include <vector>

namespace enclave
{
  static constexpr size_t InvalidSessionId = std::numeric_limits<size_t>::max();

  struct RpcContext
  {
    const size_t session_id;
    const CBuffer caller;
    bool is_forwarded = false;
    uint64_t seq_no;
    std::optional<jsonrpc::Pack> pack = std::nullopt;

    RpcContext(size_t session_id_, CBuffer caller_) :
      session_id(session_id_),
      caller(caller_)
    {}
  };

  class AbstractRPCResponder
  {
  public:
    virtual ~AbstractRPCResponder() {}
    virtual void reply_async(size_t id, const std::vector<uint8_t>& data) = 0;
  };
}