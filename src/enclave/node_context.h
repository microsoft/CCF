// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "historical_queries_interface.h"
#include "node/rpc/node_interface.h"

namespace ccfapp
{
  struct AbstractNodeContext
  {
    virtual ~AbstractNodeContext() = default;

    virtual ccf::historical::AbstractStateCache& get_historical_state() = 0;
    virtual ccf::AbstractNodeState& get_node_state() = 0;
  };
}
