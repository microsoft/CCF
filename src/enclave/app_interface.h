// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "historical_queries_interface.h"
#include "node/rpc/node_interface.h"
#include "node/rpc/user_frontend.h"

namespace ccfapp
{
  struct AbstractNodeContext
  {
    virtual ~AbstractNodeContext() = default;

    virtual ccf::historical::AbstractStateCache& get_historical_state() = 0;
    virtual ccf::AbstractNodeState& get_node_state() = 0;
  };

  // SNIPPET_START: rpc_handler
  /** To be implemented by the application to be registered by CCF.
   *
   * @param network Access to the network's replicated tables
   * @param context Access to node and host services
   *
   * @return Shared pointer to the application handler instance
   */
  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    ccf::NetworkTables& network, AbstractNodeContext& context);
  // SNIPPET_END: rpc_handler
}
