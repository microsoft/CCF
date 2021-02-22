// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "frontend.h"
#include "node/client_signatures.h"
#include "node/network_tables.h"

namespace ccf
{
  /** The CCF application must be an instance of UserRpcFrontend
   */
  class UserRpcFrontend : public RpcFrontend
  {
  public:
    UserRpcFrontend(kv::Store& tables, EndpointRegistry& h) :
      RpcFrontend(tables, h)
    {}

    void open(std::optional<crypto::Pem*> identity = std::nullopt) override
    {
      RpcFrontend::open(identity);
      endpoints.openapi_info.title = "CCF Application API";
    }
  };

  class UserEndpointRegistry : public CommonEndpointRegistry
  {
  public:
    UserEndpointRegistry(ccf::AbstractNodeState& node) :
      CommonEndpointRegistry(
        get_actor_prefix(ActorsType::users), node, Tables::USER_CERT_DERS)
    {}
  };

  class SimpleUserRpcFrontend : public UserRpcFrontend
  {
  protected:
    UserEndpointRegistry common_handlers;

  public:
    SimpleUserRpcFrontend(
      kv::Store& tables, ccf::AbstractNodeState& node_state) :
      UserRpcFrontend(tables, common_handlers),
      common_handlers(node_state)
    {}

    // Forward these methods so that apps can write foo(...); rather than
    // endpoints.foo(...);
    template <typename... Ts>
    ccf::EndpointRegistry::Endpoint make_endpoint(Ts&&... ts)
    {
      return endpoints.make_endpoint(std::forward<Ts>(ts)...);
    }

    template <typename... Ts>
    ccf::EndpointRegistry::Endpoint make_read_only_endpoint(Ts&&... ts)
    {
      return endpoints.make_read_only_endpoint(std::forward<Ts>(ts)...);
    }

    template <typename... Ts>
    ccf::EndpointRegistry::Endpoint make_command_endpoint(Ts&&... ts)
    {
      return endpoints.make_command_endpoint(std::forward<Ts>(ts)...);
    }
  };
}
