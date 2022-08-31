// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/http_consts.h"
#include "grpc.h"
#include "kv.pb.h"

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

  public:
    EndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      install_registry_service();

      install_kv_service();

      // auto do_echo = [this](ccf::endpoints::EndpointContext& ctx) {
      //   CCF_APP_INFO("ECHO HANDLER BEGIN");

      //   const auto headers = ctx.rpc_ctx->get_request_headers();
      //   CCF_APP_INFO("Request contains {} headers", headers.size());
      //   for (const auto& [k, v] : headers)
      //   {
      //     CCF_APP_INFO("  {} = {}", k, v);
      //   }

      //   echo_header(ctx.rpc_ctx, http::headers::CONTENT_TYPE);

      //   ctx.rpc_ctx->set_response_body(ctx.rpc_ctx->get_request_body());
      //   ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      //   CCF_APP_INFO("ECHO HANDLER END");
      // };

      // make_endpoint("ccf.Echo/Echo", HTTP_POST, do_echo,
      // ccf::no_auth_required)
      //   .install();

      auto put = [this](
                   ccf::endpoints::EndpointContext& ctx,
                   ccf::KVKeyValue&& payload) {
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
        "ccf.KV/Put",
        HTTP_POST,
        ccf::grpc_adapter<ccf::KVKeyValue, void>(put),
        ccf::no_auth_required)
        .install();
    }
  };
} // namespace externalexecutor

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<externalexecutor::EndpointRegistry>(context);
  }
} // namespace ccfapp