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
  // Eventually, this should extend BaseEndpointRegistry, rather than
  // CommonEndpointRegistry. But for now, we still support the old gov API by
  // extending this, and that includes the common endpoints
  class GovEndpointRegistry : public CommonEndpointRegistry
  {
  private:
    NetworkState& network;
    ShareManager share_manager;

  public:
    GovEndpointRegistry(
      NetworkState& network_, ccfapp::AbstractNodeContext& context_) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::members), context_),
      network(network_),
      share_manager(network_.ledger_secrets)
    {}

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

    bool request_needs_root(const RpcContext& rpc_ctx) override
    {
      return CommonEndpointRegistry::request_needs_root(rpc_ctx) ||
        (rpc_ctx.get_request_verb() == HTTP_POST &&
         rpc_ctx.get_request_path() == "/gov/members/proposals:create");
    }

    // Log these events on /gov frontend. Everything here should be public, so
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
      const auto api_version = get_api_version(ctx);
      if (api_version.has_value())
      {
        switch (api_version.value())
        {
          case ApiVersion::preview_v1:
          {
            ctx.rpc_ctx->set_response_body(schema::v2023_06_01_preview);
            ctx.rpc_ctx->set_response_header(
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::JSON);
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            break;
          }
        }
      }
      else
      {
        CommonEndpointRegistry::api_endpoint(ctx);
      }
    }
  };
}