// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"

namespace ccf
{
  // Partial implementation of RpcContext, private to the framework (not visible
  // to apps). Serves 2 purposes:
  // - Default implementation of simple methods accessing member fields
  // - Adding methods like `serialise_response()`, required by frontends
  class RpcContextImpl : public RpcContext
  {
  protected:
    std::shared_ptr<SessionContext> session;

  public:
    RpcContextImpl(const std::shared_ptr<SessionContext>& s) : session(s) {}

    std::shared_ptr<SessionContext> get_session_context() const override
    {
      return session;
    }

    ccf::ClaimsDigest claims;
    void set_claims_digest(ccf::ClaimsDigest::Digest&& digest) override
    {
      claims.set(std::move(digest));
    }

    ccf::PathParams path_params = {};
    virtual const ccf::PathParams& get_request_path_params() override
    {
      return path_params;
    }

    bool is_create_request = false;
    bool execute_on_node = false;

    virtual void set_tx_id(const ccf::TxID& tx_id) = 0;
    virtual bool should_apply_writes() const = 0;
    virtual void reset_response() = 0;
    virtual std::vector<uint8_t> serialise_response() const = 0;
    virtual const std::vector<uint8_t>& get_serialised_request() = 0;
  };
}