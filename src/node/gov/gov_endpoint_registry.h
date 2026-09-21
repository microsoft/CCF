// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
#include "node/gov/api_schema.h"
#include "node/gov/api_version.h"
#include "node/gov/handlers/acks.h"
#include "node/gov/handlers/proposals.h"
#include "node/gov/handlers/recovery.h"
#include "node/gov/handlers/service_state.h"
#include "node/gov/handlers/transactions.h"
#include "node/share_manager.h"

namespace ccf
{
  class GovEndpointRegistry : public CommonEndpointRegistry
  {
  private:
    static constexpr auto LATEST_API_DOCUMENT_VERSION = "5.0.0";

    NetworkState& network;
    ShareManager share_manager;

  public:
    GovEndpointRegistry(
      NetworkState& network_, ccf::AbstractNodeContext& context_) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::members), context_),
      network(network_),
      share_manager(network_.ledger_secrets)
    {
      openapi_info.title = "CCF Governance";
      openapi_info.description =
        "The governance API implemented by this CCF build. This document "
        "describes the moving 'latest' API and does not guarantee that older "
        "document versions remain available.";
      openapi_info.document_version = LATEST_API_DOCUMENT_VERSION;
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      ccf::gov::endpoints::init_ack_handlers(*this, network, share_manager);
      ccf::gov::endpoints::init_proposals_handlers(*this, network, context);
      ccf::gov::endpoints::init_recovery_handlers(
        *this, share_manager, context);
      ccf::gov::endpoints::init_service_state_handlers(*this);
      ccf::gov::endpoints::init_transactions_handlers(*this);
    }

    void build_api(nlohmann::json& document, ccf::kv::ReadOnlyTx& tx) override
    {
      CommonEndpointRegistry::build_api(document, tx);

      const auto api_version_parameter = nlohmann::json{
        {"name", "api-version"},
        {"in", "query"},
        {"required", false},
        {"description",
         "Optional API selector. 'latest' selects the API implemented by this "
         "CCF build and does not identify a frozen contract. Dated versions "
         "select frozen compatibility contracts while they remain supported."},
        {"schema",
         {
           {"type", "string"},
           {"default", "latest"},
         }}};

      for (const auto& [path, path_item] : document["paths"].items())
      {
        (void)path;
        for (const auto& [method, operation] : path_item.items())
        {
          (void)method;
          if (operation.is_object())
          {
            // OpenAPI has no security scheme for a signature carried in the
            // request body. The application/cose request body documents COSE
            // authentication for governance write operations.
            operation.erase("security");
            if (operation.contains("requestBody"))
            {
              operation["requestBody"]["required"] = true;
            }
          }
        }

        if (path_item.contains("parameters"))
        {
          for (auto& parameter : path_item["parameters"])
          {
            const auto& name = parameter["name"];
            if (
              name == "memberId" || name == "nodeId" || name == "proposalId" ||
              name == "userId")
            {
              parameter["schema"]["pattern"] = "^[a-f0-9]{64}$";
            }
            else if (name == "transactionId")
            {
              parameter["schema"]["pattern"] = "^[0-9]+\\.[0-9]+$";
            }
          }
        }

        ds::openapi::parameters(path_item).push_back(api_version_parameter);
      }

      document["components"].erase("securitySchemes");
    }

    bool request_needs_root(const RpcContext& rpc_ctx) override
    {
      return CommonEndpointRegistry::request_needs_root(rpc_ctx) ||
        (rpc_ctx.get_request_verb() == HTTP_POST &&
         rpc_ctx.get_request_path() == "/gov/members/proposals:create");
    }

    // Log these events on /gov frontend. Everything here is public, so
    // safe to display in clear in the log
    void handle_event_request_completed(
      const ccf::endpoints::RequestCompletedEvent& event) override
    {
      GOV_INFO_FMT(
        "RequestCompletedEvent: {} {} {} {}ms {} attempt(s)",
        event.method,
        event.dispatch_path,
        event.status,
        event.exec_time.count(),
        event.attempts);
    }

    void handle_event_dispatch_failed(
      const ccf::endpoints::DispatchFailedEvent& event) override
    {
      GOV_INFO_FMT("DispatchFailedEvent: {} {}", event.method, event.status);
    }

    void api_endpoint(ccf::endpoints::ReadOnlyEndpointContext& ctx) override
    {
      using namespace ccf::gov::endpoints;

      const auto api_version = get_api_version(
        ctx, ApiVersion::MIN, MissingApiVersionPolicy::UseLatest);
      if (!api_version.has_value())
      {
        return;
      }

      switch (api_version.value())
      {
        case ApiVersion::preview_v1:
        {
          ctx.rpc_ctx->set_response_body(schema::v2023_06_01_preview);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }
        case ApiVersion::v1:
        {
          ctx.rpc_ctx->set_response_body(schema::v2024_07_01);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }
        case ApiVersion::Latest:
        {
          CommonEndpointRegistry::api_endpoint(ctx);
          return;
        }
      }
    }
  };
}