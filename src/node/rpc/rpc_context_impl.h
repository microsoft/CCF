// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"
#include "endpoints/grpc/grpc_status.h"
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

    virtual void set_error(
      http_status status,
      const std::string& code,
      std::string&& msg,
      const std::vector<ccf::ODataErrorDetails>& details = {}) override
    {
      auto content_type = get_request_header(http::headers::CONTENT_TYPE);
      if (
        content_type.has_value() &&
        content_type.value() == http::headervalues::contenttype::GRPC)
      {
        set_grpc_error(http_status_to_grpc(status), std::move(msg));
      }
      else
      {
        nlohmann::json body = ccf::ODataErrorResponse{
          ccf::ODataError{code, std::move(msg), details}};
        set_response_json(body, status);
      }
    }

    void set_error(ccf::ErrorDetails&& error) override
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg)}};
      set_response_json(body, error.status);
    }

    void set_response_json(nlohmann::json& body, http_status status)
    {
      // Set error_handler to replace, to avoid throwing if the error message
      // contains non-UTF8 characters. Other args are default values
      const auto s =
        body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
      set_response_status(status);
      set_response_body(std::vector<uint8_t>(s.begin(), s.end()));
      set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
    }

    void set_grpc_error(grpc_status grpc_status, std::string&& msg)
    {
      if (http_version != HttpVersion::HTTP2)
      {
        throw std::logic_error("Cannot set gRPC error on non-HTTP/2 interface");
      }

      set_response_status(HTTP_STATUS_OK);
      set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC);
      set_response_trailer(grpc::make_status_trailer(grpc_status));
      set_response_trailer(grpc::make_message_trailer(msg));
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