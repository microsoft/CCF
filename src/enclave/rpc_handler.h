// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/tx.h"
#include "forwarder_types.h"

#include <chrono>
#include <limits>
#include <stdint.h>
#include <vector>

namespace ccf::kv
{
  class CommittableTx;
}

namespace ccf
{
  class RpcContextImpl;

  class RpcHandler
  {
  public:
    virtual ~RpcHandler() = default;

    // Used by enclave to initialise and tick frontends
    virtual void set_sig_intervals(
      size_t sig_tx_interval, size_t sig_ms_interval) = 0;
    virtual void set_cmd_forwarder(
      std::shared_ptr<AbstractForwarder> cmd_forwarder_) = 0;
    virtual void tick(std::chrono::milliseconds /*elapsed*/) {}
    virtual void open() = 0;
    virtual bool is_open() = 0;

    // Used by rpcendpoint to process incoming client RPCs
    virtual void process(std::shared_ptr<RpcContextImpl> ctx) = 0;
  };
}
