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

namespace kv
{
  class CommittableTx;
}

namespace ccf
{
  class RpcContextImpl;

  class RpcHandler
  {
  public:
    virtual ~RpcHandler() {}

    // Used by enclave to initialise and tick frontends
    virtual void set_sig_intervals(
      size_t sig_tx_interval, size_t sig_ms_interval) = 0;
    virtual void set_cmd_forwarder(
      std::shared_ptr<AbstractForwarder> cmd_forwarder_) = 0;
    virtual void tick(std::chrono::milliseconds) {}
    virtual void open(std::optional<crypto::Pem*> identity = std::nullopt) = 0;
    virtual bool is_open(kv::Tx& tx) = 0;
    virtual bool is_open() = 0;

    using DoneCB = std::function<void(std::shared_ptr<RpcContextImpl>&& ctx)>;
    static void default_done_cb(std::shared_ptr<RpcContextImpl>&& ctx) {}

    using ExceptionCB = std::function<void(const std::exception& e)>;
    static void default_exception_cb(const std::exception& e)
    {
      throw e;
    }

    // Used by rpcendpoint to process incoming client RPCs
    virtual void process(
      std::shared_ptr<RpcContextImpl> ctx,
      DoneCB&& done_cb = default_done_cb,
      ExceptionCB&& exception_cb = default_exception_cb) = 0;
  };
}
