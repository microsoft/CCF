// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
#include "enclave/node_context.h"
#include "frontend.h"
#include "node/network_tables.h"

namespace ccf
{
  class UserEndpointRegistry : public CommonEndpointRegistry
  {
  public:
    UserEndpointRegistry(ccfapp::AbstractNodeContext& context) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::users), context)
    {}
  };

  class SimpleUserRpcFrontend : public RpcFrontend
  {
  protected:
    UserEndpointRegistry common_handlers;

  public:
    SimpleUserRpcFrontend(
      kv::Store& tables, ccfapp::AbstractNodeContext& context) :
      RpcFrontend(tables, common_handlers),
      common_handlers(context)
    {}
  };
}
