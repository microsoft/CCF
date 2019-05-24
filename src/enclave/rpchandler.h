// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/buffer.h"

#include <chrono>
#include <limits>
#include <stdint.h>
#include <vector>

namespace enclave
{
  static constexpr size_t InvalidSessionId = std::numeric_limits<size_t>::max();

  struct RpcContext
  {
    const size_t session_id;
    const CBuffer caller;
    bool is_forwarded = false;
    const ccf::ActorsType actor;

    RpcContext(
      size_t session_id_,
      CBuffer caller_,
      ccf::ActorsType actor_ = ccf::ActorsType::unknown) :
      session_id(session_id_),
      caller(caller_),
      actor(actor_)
    {}
  };

  class RpcHandler
  {
  public:
    virtual ~RpcHandler() {}

    virtual std::vector<uint8_t> process(
      RpcContext& rpc_ctx, const std::vector<uint8_t>& input) = 0;

    virtual void tick(std::chrono::milliseconds elapsed_ms_count) {}
  };
}
