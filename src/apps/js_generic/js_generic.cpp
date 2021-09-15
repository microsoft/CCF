// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/js_crypto_plugin.h"
#include "ccf/js_openenclave_plugin.h"
#include "js_generic_base.h"

namespace ccfapp
{
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context)
  {
    return get_rpc_handler_impl(network, context);
  }

  std::vector<ccf::js::FFIPlugin> get_js_plugins()
  {
    return {ccf::js::crypto_plugin, ccf::js::openenclave_plugin};
  }

} // namespace ccfapp
