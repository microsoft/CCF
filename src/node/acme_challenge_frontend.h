// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/actors.h"
#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/endpoint_registry.h"
#include "node/network_state.h"
#include "node/rpc/frontend.h"

namespace ccf
{
  class ACMERpcEndpoints : public CommonEndpointRegistry
  {
  public:
    ACMERpcEndpoints(
      NetworkState& network, ccfapp::AbstractNodeContext& context) :
      CommonEndpointRegistry(
        get_actor_prefix(ActorsType::acme_challenge), context)
    {
      auto handler = [this](auto& ctx) {
        http_status response_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        std::string response_body;

        const auto& path_params = ctx.rpc_ctx->get_request_path_params();
        const auto url_token_it = path_params.find("token");

        if (url_token_it == path_params.end())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          ctx.rpc_ctx->set_response_body("no token in URL");
        }

        std::string token = url_token_it->second;
        LOG_DEBUG_FMT("ACME: challenge request for token '{}'", token);

        auto tit = prepared_responses.find(token);
        if (tit == prepared_responses.end())
        {
          auto prit = prepared_responses.find("");
          if (prit != prepared_responses.end())
          {
            response_status = HTTP_STATUS_OK;
            response_body = token + "." + prit->second;
          }
          else
          {
            response_status = HTTP_STATUS_NOT_FOUND;
            response_body =
              fmt::format("Challenge response for token '{}' not found", token);
          }
        }
        else
        {
          response_status = HTTP_STATUS_OK;
          response_body = token + "." + tit->second;
        }

        ctx.rpc_ctx->set_response_status(response_status);
        ctx.rpc_ctx->set_response_body(std::move(response_body));
      };

      make_endpoint("/{token}", HTTP_GET, handler, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<void, std::string>()
        .install();
    }

    virtual ~ACMERpcEndpoints() = default;

    void add(const std::string& token, const std::string& response)
    {
      LOG_TRACE_FMT(
        "ACME: challenge server received response for token '{}' ({})",
        token,
        response);

      prepared_responses.emplace(token, response);
    }

    void remove(const std::string& token)
    {
      prepared_responses.erase(token);
    }

  protected:
    std::map<std::string, std::string> prepared_responses;
  };

  class ACMERpcFrontend : public RpcFrontend
  {
  protected:
    ACMERpcEndpoints endpoints;

  public:
    ACMERpcFrontend(
      NetworkState& network, ccfapp::AbstractNodeContext& context) :
      RpcFrontend(*network.tables, endpoints, context),
      endpoints(network, context)
    {}

    virtual ~ACMERpcFrontend() = default;

    void add(const std::string& token, const std::string& response)
    {
      endpoints.add(token, response);
    }

    void remove(const std::string& token)
    {
      endpoints.remove(token);
    }
  };
}
