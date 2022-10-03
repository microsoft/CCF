// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"

#include <vector>

namespace ccf
{
  class RpcContextImpl;

  class AbstractForwarder
  {
  public:
    virtual ~AbstractForwarder() {}

    virtual bool forward_command(
      std::shared_ptr<ccf::RpcContextImpl> rpc_ctx,
      const ccf::NodeId& to,
      const std::vector<uint8_t>& caller_cert,
      const std::chrono::milliseconds& timeout =
        std::chrono::milliseconds(3'000)) = 0;
  };
}