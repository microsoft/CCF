// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../ds/buffer.h"

#include <chrono>
#include <stdint.h>
#include <vector>

namespace enclave
{
  class RpcHandler
  {
  public:
    virtual ~RpcHandler() {}

    virtual std::vector<uint8_t> process(
      CBuffer caller, const std::vector<uint8_t>& input) = 0;

    virtual std::vector<uint8_t> process_forwarded(
      const uint8_t* data, size_t size) = 0;

    virtual void tick(
      std::chrono::system_clock::time_point now,
      std::chrono::milliseconds elapsed)
    {}
  };
}
