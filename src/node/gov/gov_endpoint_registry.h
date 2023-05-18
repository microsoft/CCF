// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
#include "node/gov/api_version.h"
#include "node/gov/transactions_handlers.h"
#include "node/share_manager.h"

namespace ccf
{
  // TODO: Eventually, this should extend BaseEndpointRegistry, rather than
  // CommonEndpointRegistry!
  class GovEndpointRegistry : public CommonEndpointRegistry
  {
  public:
    GovEndpointRegistry(
      NetworkState& network_,
      ccfapp::AbstractNodeContext& context_,
      ShareManager& share_manager_) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::members), context_)
    {}

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      ccf::gov::endpoints::init_transactions_handlers(*this);
    }
  };
}