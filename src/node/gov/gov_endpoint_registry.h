// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
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
  };
}