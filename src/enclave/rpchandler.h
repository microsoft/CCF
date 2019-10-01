// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/buffer.h"
#include "enclavetypes.h"

#include <chrono>
#include <limits>
#include <stdint.h>
#include <vector>

namespace enclave
{
  class RpcHandler
  {
  public:
    virtual ~RpcHandler() {}

    virtual std::vector<uint8_t> process(
      RPCContext& ctx, const std::vector<uint8_t>& input) = 0;

    struct ProcessPbftResp
    {
      std::vector<uint8_t> result;
      crypto::Sha256Hash merkle_root;
      kv::Version version;
    };

    virtual ProcessPbftResp process_pbft(
      RPCContext& ctx, const std::vector<uint8_t>& input) = 0;

    virtual void tick(std::chrono::milliseconds elapsed_ms_count) {}
  };
}
