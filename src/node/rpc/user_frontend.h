// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_deprecated.h"
#include "frontend.h"
#include "node/client_signatures.h"
#include "node/network_tables.h"

namespace ccf
{
  /** The CCF application must be an instance of UserRpcFrontend
   */
  class UserRpcFrontend : public RpcFrontend
  {
  protected:
    std::string invalid_caller_error_message() const override
    {
      return "Could not find matching user certificate";
    }

    Users* users;

  public:
    UserRpcFrontend(kv::Store& tables, EndpointRegistry& h) :
      RpcFrontend(
        tables,
        h,
        tables.get<ClientSignatures>(Tables::USER_CLIENT_SIGNATURES)),
      users(tables.get<Users>(Tables::USERS))
    {}

    void open() override
    {
      RpcFrontend::open();
    }

    bool lookup_forwarded_caller_cert(
      std::shared_ptr<enclave::RpcContext> ctx, kv::Tx& tx) override
    {
      // Lookup the calling user's certificate from the forwarded caller id
      auto users_view = tx.get_view(*users);
      auto caller = users_view->get(ctx->session->original_caller->caller_id);
      if (!caller.has_value())
      {
        return false;
      }

      ctx->session->caller_cert = caller.value().cert.raw();
      return true;
    }

    // Forward these methods so that apps can write foo(...); rather than
    // endpoints.foo(...);
    template <typename... Ts>
    ccf::EndpointRegistry::Endpoint& install(Ts&&... ts)
    {
      return endpoints.install(std::forward<Ts>(ts)...);
    }

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

  class UserEndpointRegistry : public CommonEndpointRegistry
  {
  public:
    UserEndpointRegistry(kv::Store& store) :
      CommonEndpointRegistry(store, Tables::USER_CERT_DERS)
    {}

    UserEndpointRegistry(NetworkTables& network) :
      CommonEndpointRegistry(*network.tables, Tables::USER_CERT_DERS)
    {}
  };

  using UserHandlerRegistry CCF_DEPRECATED(
    "Handlers have been renamed to Endpoints. Please use "
    "UserEndpointRegistry") = UserEndpointRegistry;

  class SimpleUserRpcFrontend : public UserRpcFrontend
  {
  protected:
    UserEndpointRegistry common_handlers;

  public:
    SimpleUserRpcFrontend(kv::Store& tables) :
      UserRpcFrontend(tables, common_handlers),
      common_handlers(tables)
    {}
  };
}
