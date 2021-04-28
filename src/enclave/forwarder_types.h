// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rpc_context.h"

#include <vector>

namespace enclave
{
  class AbstractRPCResponder
  {
  public:
    virtual ~AbstractRPCResponder() {}
    virtual bool reply_async(size_t id, std::vector<uint8_t>&& data) = 0;
  };

  class AbstractForwarder
  {
  public:
    virtual ~AbstractForwarder() {}

    virtual bool forward_command(
      std::shared_ptr<enclave::RpcContext> rpc_ctx,
      const ccf::NodeId& to,
      std::set<ccf::NodeId> nodes,
      const std::vector<uint8_t>& caller_cert) = 0;

    virtual void send_request_hash_to_nodes(
      std::shared_ptr<enclave::RpcContext> rpc_ctx,
      std::set<ccf::NodeId> nodes,
      const ccf::NodeId& skip_node) = 0;
  };
}