// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
#include "node/gov/api_version.h"
#include "node/gov/handlers/acks.h"
// #include "node/gov/handlers/proposals.h"
#include "node/gov/handlers/recovery.h"
// #include "node/gov/handlers/service_state.h"
#include "node/gov/handlers/transactions.h"
#include "node/share_manager.h"

namespace ccf
{
  // TODO: Eventually, this should extend BaseEndpointRegistry, rather than
  // CommonEndpointRegistry!
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
      // ccf::gov::endpoints::init_proposals_handlers(*this);
      ccf::gov::endpoints::init_recovery_handlers(*this);
      // ccf::gov::endpoints::init_service_state_handlers(*this);
      ccf::gov::endpoints::init_transactions_handlers(*this);
    }
  };
}