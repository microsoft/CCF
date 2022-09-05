// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

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

    void echo_header(
      std::shared_ptr<ccf::RpcContext>& rpc_ctx, const std::string_view& sv)
    {
      const auto header_val = rpc_ctx->get_request_header(sv);
      if (header_val.has_value())
      {
        rpc_ctx->set_response_header(sv, *header_val);
      }
    }

    ccf::endpoints::EndpointFunction grpc_response_status_wrapper(
      const ccf::endpoints::EndpointFunction& fn)
    {
      return [fn](ccf::endpoints::EndpointContext& ctx) {
        fn(ctx);
        ctx.rpc_ctx->set_response_trailer("grpc-status", 0);
        ctx.rpc_ctx->set_response_trailer("grpc-message", "Ok");
      };
    }

  public:
    EndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      install_registry_service();

      install_kv_service();

      auto do_echo = [this](ccf::endpoints::EndpointContext& ctx) {
        CCF_APP_INFO("ECHO HANDLER BEGIN");

        const auto headers = ctx.rpc_ctx->get_request_headers();
        CCF_APP_INFO("Request contains {} headers", headers.size());
        for (const auto& [k, v] : headers)
        {
          CCF_APP_INFO("  {} = {}", k, v);
        }

        echo_header(ctx.rpc_ctx, http::headers::CONTENT_TYPE);

        ctx.rpc_ctx->set_response_body(ctx.rpc_ctx->get_request_body());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        CCF_APP_INFO("ECHO HANDLER END");
      };

      make_endpoint(
        "ccf.Echo/Echo",
        HTTP_POST,
        grpc_response_status_wrapper(do_echo),
        ccf::no_auth_required)
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