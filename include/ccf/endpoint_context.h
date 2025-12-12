// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/tx_status.h"

#include <functional>
#include <memory>

namespace ccf
{
  class RpcContext;
}

/**
 * Defines the different types of context an Endpoint can operate over,
 * and the types of handler functions which process them.
 */

namespace ccf::endpoints
{
  // Commands are endpoints which do not interact with the kv, even to read
  struct CommandEndpointContext
  {
    virtual ~CommandEndpointContext() = default;

    CommandEndpointContext(const std::shared_ptr<ccf::RpcContext>& r) :
      rpc_ctx(r)
    {}

    std::shared_ptr<ccf::RpcContext> rpc_ctx;
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
    EndpointContext(const std::shared_ptr<ccf::RpcContext>& r, ccf::kv::Tx& t) :
      CommandEndpointContext(r),
      tx(t)
    {}

    ccf::kv::Tx& tx;
  };
  using EndpointFunction = std::function<void(EndpointContext& args)>;

  using LocallyCommittedEndpointFunction =
    std::function<void(CommandEndpointContext& ctx, const ccf::TxID& txid)>;

  using ConsensusCommittedEndpointFunction = std::function<void(
    std::shared_ptr<ccf::RpcContext> rpc_ctx,
    const ccf::TxID& txid,
    ccf::FinalTxStatus status)>;

  // Read-only endpoints can only get values from the kv, they cannot write
  struct ReadOnlyEndpointContext : public CommandEndpointContext
  {
    ReadOnlyEndpointContext(
      const std::shared_ptr<ccf::RpcContext>& r, ccf::kv::ReadOnlyTx& t) :
      CommandEndpointContext(r),
      tx(t)
    {}

    ccf::kv::ReadOnlyTx& tx;
  };
  using ReadOnlyEndpointFunction =
    std::function<void(ReadOnlyEndpointContext& args)>;
}
