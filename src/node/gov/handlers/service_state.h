// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"

namespace ccf::gov::endpoints
{
  void init_service_state_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_constitution = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::v0_0_1_preview:
        default:
        {
          auto constitution_handle =
            ctx.tx.template ro<ccf::Constitution>(ccf::Tables::CONSTITUTION);
          auto constitution = constitution_handle->get();

          if (!constitution.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "Constitution not found");
          }

          // Return raw JS constitution in body
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(constitution.value()));
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JAVASCRIPT);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/constitution",
        HTTP_GET,
        api_version_adapter(get_constitution),
        no_auth_required)
      .install();

    // TODO:
    // /service/info
    // /service/javascript-app
    // /service/join-policy
    // /service/jwk
    // /service/members
    // /service/members/{memberId}
    // /service/nodes
    // /service/nodes/{nodeId}
  }
}