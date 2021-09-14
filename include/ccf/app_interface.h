// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <memory>
#include <vector>

namespace ccf
{
  // Forward declarations
  class RpcFrontend;

  struct NetworkTables;
}

namespace js
{
  struct FFIPlugin;
}

namespace ccfapp
{
  // Forward declaration
  struct AbstractNodeContext;

  // SNIPPET_START: rpc_handler
  /** To be implemented by the application to be registered by CCF.
   *
   * @param network Access to the network's replicated tables
   * @param context Access to node and host services
   *
   * @return Shared pointer to the application handler instance
   */
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    ccf::NetworkTables& network, AbstractNodeContext& context);
  // SNIPPET_END: rpc_handler

  std::vector<js::FFIPlugin> get_js_plugins();
}
