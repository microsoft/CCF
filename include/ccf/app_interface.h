// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/actors.h"
#include "ccf/ccf_deprecated.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/js_plugin.h"
#include "ccf/node_context.h"

#include <memory>
#include <vector>

// Forward declarations, can be removed with deprecation
namespace ccf
{
  class RpcFrontend;
}

namespace kv
{
  class Store;
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
  /** To be implemented by the application. Creates a collection of endpoints
   * which will be exposed to callers under /app.
   *
   * @param context Access to node and host services
   *
   * @return Unique pointer to the endpoint registry instance
   */
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context);

  /** To be implemented by the application.
   *
   * @return Vector of JavaScript FFI plugins
   */
  std::vector<ccf::js::FFIPlugin> get_js_plugins();
  // SNIPPET_END: app_interface
}
