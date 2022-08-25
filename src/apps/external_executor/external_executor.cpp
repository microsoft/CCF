// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/http_consts.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace externalexecutor
{
  class EndpointRegistry : public ccf::UserEndpointRegistry
  {
    void install_registry_service() {}

    void install_kv_service() {}

  public:
    EndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      install_registry_service();

      install_kv_service();

      auto do_echo = [this](ccf::endpoints::EndpointContext& ctx) {
        const auto content_type =
          ctx.rpc_ctx->get_request_header(http::headers::CONTENT_TYPE);
        if (content_type.has_value())
        {
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, *content_type);
        }

        ctx.rpc_ctx->set_response_body(ctx.rpc_ctx->get_request_body());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };

      make_endpoint("ccf.Echo/Echo", HTTP_POST, do_echo, ccf::no_auth_required)
        .install();
    }
  };
} // namespace app

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<externalexecutor::EndpointRegistry>(context);
  }
} // namespace ccfapp