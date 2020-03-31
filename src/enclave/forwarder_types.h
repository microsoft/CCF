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
    virtual bool reply_async(size_t id, const std::vector<uint8_t>& data) = 0;
  };

  class AbstractForwarder
  {
  public:
    virtual ~AbstractForwarder() {}

    virtual bool forward_command(
      std::shared_ptr<enclave::RpcContext> rpc_ctx,
      ccf::NodeId to,
      ccf::CallerId caller_id,
      const std::vector<uint8_t>& caller_cert) = 0;
  };
}