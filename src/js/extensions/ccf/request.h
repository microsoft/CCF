// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/endpoint_context.h"
#include "ccf/rpc_context.h"
#include "js/core/wrapped_value.h"
#include "js/extensions/extension_interface.h"

namespace ccf::js
{
  struct JSDynamicEndpoint;
}

// TODO: This should live by the JSGeneric app
namespace ccf::js::extensions
{
  /**
   **/
  class RequestExtension : public ExtensionInterface
  {
  public:
    ccf::RpcContext* rpc_ctx;

    RequestExtension(ccf::RpcContext* rc) : rpc_ctx(rc) {}

    void install(js::core::Context& ctx) override;

    js::core::JSWrappedValue create_request_obj(
      const ccf::js::JSDynamicEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      js::core::Context& ctx,
      ccf::BaseEndpointRegistry* registry);
  };
}
