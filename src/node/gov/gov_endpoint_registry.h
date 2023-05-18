// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
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
  };

  // Eventually, but not yet
  // class GovRpcFrontend : public RpcFrontend
  // {
  // protected:
  //   GovEndpointRegistry gov_endpoints;

  // public:
  //   GovRpcFrontend(
  //     NetworkState& network,
  //     ccfapp::AbstractNodeContext& context,
  //     ShareManager& share_manager) :
  //     RpcFrontend(*network.tables, member_endpoints, context),
  //     gov_endpoints(network, context, share_manager)
  //   {}
  // };
}