// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/js_openenclave_plugin.h"
#include "js_v8_base.h"

namespace ccfapp
{
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context)
  {
    return get_rpc_handler_impl(network, context);
  }

  std::vector<ccf::js::FFIPlugin> get_js_plugins()
  {
    return {};
  }

} // namespace ccfapp
