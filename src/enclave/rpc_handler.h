// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/buffer.h"
#include "forwarder_types.h"

#include <chrono>
#include <limits>
#include <stdint.h>
#include <vector>

namespace kv
{
  class Tx;
}

namespace enclave
{
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
    virtual void open(std::optional<tls::Pem*> identity = std::nullopt) = 0;
    virtual bool is_open(kv::Tx& tx) = 0;

    // Used by rpcendpoint to process incoming client RPCs
    virtual std::optional<std::vector<uint8_t>> process(
      std::shared_ptr<RpcContext> ctx) = 0;

    // Used by BFT to execute commands
    struct ProcessBftResp
    {
      std::vector<uint8_t> result;
      kv::Version version;
    };

    virtual ProcessBftResp process_bft(
      std::shared_ptr<enclave::RpcContext> ctx) = 0;
    virtual ProcessBftResp process_bft(
      std::shared_ptr<enclave::RpcContext> ctx, kv::Tx& tx) = 0;
  };
}
