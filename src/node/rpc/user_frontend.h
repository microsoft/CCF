// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/app_interface.h"
#include "node/network_state.h"
#include "node/rpc/frontend.h"

namespace ccf
{
  class UserRpcFrontend : public RpcFrontend
  {
  protected:
    std::unique_ptr<ccf::BaseEndpointRegistry> endpoints;

  public:
    UserRpcFrontend(
      NetworkState& network,
      std::unique_ptr<ccf::BaseEndpointRegistry>&& endpoints_) :
      RpcFrontend(*network.tables, *endpoints_),
      endpoints(std::move(endpoints_))
    {}
  };
}
