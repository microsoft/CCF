// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js_plugin.h"

#include <memory>
#include <vector>

// Forward declarations
namespace ccf
{
  class RpcFrontend;
}

namespace kv
{
  class Store;
}

namespace ccfapp
{
  // Forward declaration
  struct AbstractNodeContext;

  // SNIPPET_START: app_interface
  /** To be implemented by the application to be registered by CCF.
   *
   * @param network Access to the network's replicated tables
   * @param context Access to node and host services
   *
   * @return Shared pointer to the application handler instance
   */
  // TODO: Does anyone even need this Store? Or can we remove it...
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    kv::Store& store, AbstractNodeContext& context);

  /** To be implemented by the application to be registered by CCF.
   *
   * @return Vector of JavaScript FFI plugins
   */
  std::vector<ccf::js::FFIPlugin> get_js_plugins();
  // SNIPPET_END: app_interface
}
