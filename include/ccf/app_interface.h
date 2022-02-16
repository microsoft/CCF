// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_deprecated.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/js_plugin.h"
#include "ccf/node_context.h"

#include <memory>
#include <vector>

// TODO: Remove these?
// Forward declarations, can be removed with deprecation
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
  CCF_DEPRECATED("Replace with make_user_endpoints")
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    kv::Store& store, AbstractNodeContext& context);
}

namespace ccf
{
  class UserEndpointRegistry : public CommonEndpointRegistry
  {
  public:
    UserEndpointRegistry(ccfapp::AbstractNodeContext& context) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::users), context)
    {}
  };
}

namespace ccfapp
{
  // SNIPPET_START: app_interface
  // TODO: Document
  std::unique_ptr<ccf::BaseEndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context);

  /** To be implemented by the application to be registered by CCF.
   *
   * @return Vector of JavaScript FFI plugins
   */
  std::vector<ccf::js::FFIPlugin> get_js_plugins();
  // SNIPPET_END: app_interface
}
