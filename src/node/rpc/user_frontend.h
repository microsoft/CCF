// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "frontend.h"
#include "node/client_signatures.h"
#include "node/network_tables.h"

namespace ccf
{
  class UserRpcFrontend : public RpcFrontend
  {
  protected:
    std::string invalid_caller_error_message() const override
    {
      return "Could not find matching user certificate";
    }

    Users* users;

  public:
    UserRpcFrontend(Store& tables, HandlerRegistry& h) :
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
      std::shared_ptr<enclave::RpcContext> ctx, Store::Tx& tx) override
    {
      // Lookup the calling user's certificate from the forwarded caller id
      auto users_view = tx.get_view(*users);
      auto caller = users_view->get(ctx->session->original_caller->caller_id);
      if (!caller.has_value())
      {
        return false;
      }

      ctx->session->caller_cert = caller.value().cert;
      return true;
    }

    // This is simply so apps can write install(...); rather than
    // handlers.install(...);
    template <typename... Ts>
    ccf::HandlerRegistry::Handler& install(Ts&&... ts)
    {
      return handlers.install(std::forward<Ts>(ts)...);
    }
  };

  class UserHandlerRegistry : public CommonHandlerRegistry
  {
  public:
    UserHandlerRegistry(Store& store) :
      CommonHandlerRegistry(store, Tables::USER_CERTS)
    {}

    UserHandlerRegistry(NetworkTables& network) :
      CommonHandlerRegistry(*network.tables, Tables::USER_CERTS)
    {}
  };

  class SimpleUserRpcFrontend : public UserRpcFrontend
  {
  protected:
    UserHandlerRegistry common_handlers;

  public:
    SimpleUserRpcFrontend(Store& tables) :
      UserRpcFrontend(tables, common_handlers),
      common_handlers(tables)
    {}
  };
}
