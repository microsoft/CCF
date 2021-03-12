// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_context.h"
#include "http/authentication/authentication_types.h"

#include <functional>
#include <memory>

/**
 * @file Defines the different types of context an Endpoint can operate over,
 * and the types of handler functions which process them.
 */

namespace ccf::endpoints
{
  // Commands are endpoints which do not interact with the kv, even to read
  struct CommandEndpointContext
  {
    CommandEndpointContext(
      const std::shared_ptr<enclave::RpcContext>& r,
      std::unique_ptr<AuthnIdentity>&& c) :
      rpc_ctx(r),
      caller(std::move(c))
    {}

    std::shared_ptr<enclave::RpcContext> rpc_ctx;
    std::unique_ptr<AuthnIdentity> caller;

    template <typename T>
    const T* try_get_caller()
    {
      return dynamic_cast<const T*>(caller.get());
    }

    template <typename T>
    const T& get_caller()
    {
      const T* ident = try_get_caller<T>();
      if (ident == nullptr)
      {
        throw std::logic_error("Asked for unprovided identity type");
      }
      return *ident;
    }
  };
  using CommandEndpointFunction =
    std::function<void(CommandEndpointContext& args)>;

  struct EndpointContext : public CommandEndpointContext
  {
    EndpointContext(
      const std::shared_ptr<enclave::RpcContext>& r,
      std::unique_ptr<AuthnIdentity>&& c,
      kv::Tx& t) :
      CommandEndpointContext(r, std::move(c)),
      tx(t)
    {}

    kv::Tx& tx;
  };
  using EndpointFunction = std::function<void(EndpointContext& args)>;

  // Read-only endpoints can only get values from the kv, they cannot write
  struct ReadOnlyEndpointContext : public CommandEndpointContext
  {
    ReadOnlyEndpointContext(
      const std::shared_ptr<enclave::RpcContext>& r,
      std::unique_ptr<AuthnIdentity>&& c,
      kv::ReadOnlyTx& t) :
      CommandEndpointContext(r, std::move(c)),
      tx(t)
    {}

    kv::ReadOnlyTx& tx;
  };
  using ReadOnlyEndpointFunction =
    std::function<void(ReadOnlyEndpointContext& args)>;
}
