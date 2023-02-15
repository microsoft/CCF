// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"

#include <vector>

namespace ccf
{
  class RpcContextImpl;

  class AbstractRPCResponder
  {
  public:
    virtual ~AbstractRPCResponder() {}
    virtual bool reply_async(
      int64_t id, bool terminate_after_reply, std::vector<uint8_t>&& data) = 0;
  };

  class AbstractForwarder
  {
  public:
    virtual ~AbstractForwarder() {}

    virtual bool forward_command(
      std::shared_ptr<ccf::RpcContextImpl> rpc_ctx,
      const ccf::NodeId& to,
      const std::vector<uint8_t>& caller_cert,
      const std::chrono::milliseconds& timeout =
        std::chrono::milliseconds(15'000)) = 0;
  };
}