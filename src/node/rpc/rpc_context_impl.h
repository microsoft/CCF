// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"
#include "node/rpc/claims.h"

namespace ccf
{
  enum class HttpVersion
  {
    HTTP1 = 0,
    HTTP2
  };

  // Partial implementation of RpcContext, private to the framework (not visible
  // to apps). Serves 2 purposes:
  // - Default implementation of simple methods accessing member fields
  // - Adding methods like `serialise_response()`, required by frontends
  class RpcContextImpl : public RpcContext
  {
  protected:
    std::shared_ptr<SessionContext> session;
    HttpVersion http_version;

    std::shared_ptr<void> user_data;

  public:
    RpcContextImpl(
      const std::shared_ptr<SessionContext>& s,
      HttpVersion v = HttpVersion::HTTP1) :
      session(s),
      http_version(v)
    {}

    std::shared_ptr<SessionContext> get_session_context() const override
    {
      return session;
    }

    virtual void set_user_data(std::shared_ptr<void> data) override
    {
      user_data = data;
    }

    virtual void* get_user_data() const override
    {
      return user_data.get();
    }

    ccf::ClaimsDigest claims = ccf::empty_claims();
    void set_claims_digest(ccf::ClaimsDigest::Digest&& digest) override
    {
      claims.set(std::move(digest));
    }

    ccf::PathParams path_params = {};
    virtual const ccf::PathParams& get_request_path_params() override
    {
      return path_params;
    }

    ccf::PathParams decoded_path_params = {};
    virtual const ccf::PathParams& get_decoded_request_path_params() override
    {
      return decoded_path_params;
    }

    HttpVersion get_http_version() const
    {
      return http_version;
    }

    bool is_create_request = false;
    bool execute_on_node = false;
    bool response_is_pending = false;
    bool terminate_session = false;

    virtual void set_tx_id(const ccf::TxID& tx_id) = 0;
    virtual bool should_apply_writes() const = 0;
    virtual void reset_response() = 0;
    virtual std::vector<uint8_t> serialise_response() const = 0;
    virtual const std::vector<uint8_t>& get_serialised_request() = 0;
  };
}