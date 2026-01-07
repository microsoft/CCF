// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
#include "ccf/node_context.h"

#include <memory>
#include <vector>

// Forward declarations, can be removed with deprecation
namespace ccf
{
  class RpcFrontend;
}

namespace ccf::kv
{
  class Store;
}

namespace ccf
{
  class UserEndpointRegistry : public CommonEndpointRegistry
  {
  public:
    UserEndpointRegistry(ccf::AbstractNodeContext& context);

    // Default behaviour is to do nothing - do NOT log summary of every request
    // as it completes. Apps may override this if they wish.
    void handle_event_request_completed(
      const ccf::endpoints::RequestCompletedEvent& event) override;

    // Default behavour is to log dispatch failures, as a coarse metric of
    // some user errors, but do not log the raw path, which may contain
    // confidential fields misformatted into the wrong url
    void handle_event_dispatch_failed(
      const ccf::endpoints::DispatchFailedEvent& event) override;
  };
}

namespace ccf
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
    ccf::AbstractNodeContext& context);
  // SNIPPET_END: app_interface
}
