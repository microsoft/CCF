// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/buffer.h"
#include "forwardertypes.h"

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

    // Used by enclave to initialise and tick frontends
    virtual void set_sig_intervals(size_t sig_max_tx_, size_t sig_max_ms_) = 0;
    virtual void set_cmd_forwarder(
      std::shared_ptr<AbstractForwarder> cmd_forwarder_) = 0;
    virtual void tick(std::chrono::milliseconds elapsed_ms_count) {}
    virtual void open() = 0;
    virtual bool is_open() = 0;

    // Used by rpcendpoint to process incoming client RPCs
    virtual std::optional<std::vector<uint8_t>> process(
      std::shared_ptr<RpcContext> ctx) = 0;

    // Used by PBFT to execute commands
    struct ProcessPbftResp
    {
      std::vector<uint8_t> result;
      crypto::Sha256Hash full_state_merkle_root;
      crypto::Sha256Hash replicated_state_merkle_root;
      kv::Version version;
    };

    virtual ProcessPbftResp process_pbft(
      std::shared_ptr<enclave::RpcContext> ctx, bool include_merkle_roots) = 0;
    virtual ProcessPbftResp process_pbft(
      std::shared_ptr<enclave::RpcContext>,
      ccf::Store::Tx& tx,
      bool playback,
      bool include_merkle_roots) = 0;
  };
}
