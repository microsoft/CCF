// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "enclave/rpc_context.h"
#include "enclave/rpc_handler.h"

#include <functional>
#include <vector>

namespace aft
{
  class RequestMessage;
  struct RequestCtx
  {
    std::shared_ptr<enclave::RpcContext> ctx;
    std::shared_ptr<enclave::RpcHandler> frontend;
  };

  using ReplyCallback = std::function<bool(
    void* owner,
    kv::TxHistory::RequestID caller_rid,
    int status,
    std::vector<uint8_t>& data)>;

  class IStateMachine
  {
  public:
    IStateMachine() = default;
    virtual ~IStateMachine() = default;

    virtual void receive_request(std::unique_ptr<RequestMessage> request) = 0;
    virtual void add_node(kv::NodeId node_id, const std::vector<uint8_t>& cert) = 0;
    virtual bool is_primary() = 0;
    virtual kv::NodeId primary() = 0;
    virtual kv::Consensus::View view() = 0;
  };

  std::unique_ptr<IStateMachine> create_state_machine(kv::NodeId my_node_id, const std::vector<uint8_t>& cert);
}