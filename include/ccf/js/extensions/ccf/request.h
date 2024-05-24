// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/endpoint_context.h"
#include "ccf/js/core/wrapped_value.h"
#include "ccf/js/extensions/extension_interface.h"
#include "ccf/rpc_context.h"

namespace ccf::js::extensions
{
  /**
   **/
  class RequestExtension : public ccf::js::extensions::ExtensionInterface
  {
  public:
    ccf::RpcContext* rpc_ctx;

    RequestExtension(ccf::RpcContext* rc) : rpc_ctx(rc) {}

    void install(ccf::js::core::Context& ctx) override;

    ccf::js::core::JSWrappedValue create_request_obj(
      ccf::js::core::Context& ctx,
      std::string_view full_request_path,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      ccf::BaseEndpointRegistry* registry);
  };
}
