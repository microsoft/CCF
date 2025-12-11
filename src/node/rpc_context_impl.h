// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/claims_digest.h"
#include "ccf/rpc_context.h"

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
    // NOLINTBEGIN(performance-move-const-arg)
    void set_claims_digest(ccf::ClaimsDigest::Digest&& digest) override
    {
      claims.set(std::move(digest));
    }
    // NOLINTEND(performance-move-const-arg)

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

    virtual void set_error(
      ccf::http_status status,
      const std::string& code,
      std::string&& msg,
      const std::vector<nlohmann::json>& details = {}) override
    {
      nlohmann::json body =
        ccf::ODataErrorResponse{ccf::ODataError{code, std::move(msg), details}};
      set_response_json(body, status);
    }

    void set_error(ccf::ErrorDetails&& error) override
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg), {}}};
      set_response_json(body, error.status);
    }

    void set_response_json(
      const nlohmann::json& body, ccf::http_status status) override
    {
      // Set error_handler to replace, to avoid throwing if the error message
      // contains non-UTF8 characters. Other args are default values
      const auto s =
        body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
      set_response_status(status);
      set_response_body(std::vector<uint8_t>(s.begin(), s.end()));
      set_response_header(
        ccf::http::headers::CONTENT_TYPE,
        http::headervalues::contenttype::JSON);
    }

    bool response_is_pending = false;
    bool terminate_session = false;

    std::optional<
      std::pair<ccf::TxID, ccf::endpoints::ConsensusCommittedEndpointFunction>>
      respond_on_commit = std::nullopt;

    virtual void set_tx_id(const ccf::TxID& tx_id) = 0;
    virtual bool should_apply_writes() const = 0;
    virtual void reset_response() = 0;
    virtual std::vector<uint8_t> serialise_response() const = 0;
    virtual const std::vector<uint8_t>& get_serialised_request() = 0;
  };
}