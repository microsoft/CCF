// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/claims_digest.h"
#include "ccf/frame_format.h"
#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
#include "ccf/odata_error.h"
#include "ccf/rest_verb.h"
#include "ccf/service/signed_req.h"
#include "ccf/tx_id.h"

#include <vector>

namespace ccf
{
  static constexpr size_t InvalidSessionId = std::numeric_limits<size_t>::max();
  using ListenInterfaceID = std::string;

  struct SessionContext
  {
    size_t client_session_id = InvalidSessionId;
    // Usually a DER certificate, may be a PEM on forwardee
    std::vector<uint8_t> caller_cert = {};
    bool is_forwarding = false;

    // Only set for RPC sessions (i.e. non-forwarded and non-internal)
    std::optional<ListenInterfaceID> interface_id = std::nullopt;

    //
    // Only set in the case of a forwarded RPC
    //
    bool is_forwarded = false;

    SessionContext(
      size_t client_session_id_,
      const std::vector<uint8_t>& caller_cert_,
      const std::optional<ListenInterfaceID>& interface_id_ = std::nullopt) :
      client_session_id(client_session_id_),
      caller_cert(caller_cert_),
      interface_id(interface_id_)
    {}
  };

  using PathParams = std::map<std::string, std::string, std::less<>>;

  class RpcContext
  {
  public:
    virtual ~RpcContext() = default;

    /// Session details
    virtual std::shared_ptr<SessionContext> get_session_context() const = 0;

    /// Request details
    virtual const std::vector<uint8_t>& get_request_body() const = 0;
    virtual const std::string& get_request_query() const = 0;
    virtual PathParams& get_request_path_params() = 0;
    virtual const ccf::RESTVerb& get_request_verb() const = 0;
    virtual std::string get_request_path() const = 0;

    virtual std::string get_method() const = 0;

    virtual const http::HeaderMap& get_request_headers() const = 0;
    virtual std::optional<std::string> get_request_header(
      const std::string_view& name) = 0;

    virtual const std::vector<uint8_t>& get_serialised_request() = 0;
    virtual const std::string& get_request_url() const = 0;

    virtual ccf::FrameFormat frame_format() const = 0;

    /// Response details
    virtual void set_response_body(const std::vector<uint8_t>& body) = 0;
    virtual void set_response_body(std::vector<uint8_t>&& body) = 0;
    virtual void set_response_body(std::string&& body) = 0;

    virtual void set_response_status(int status) = 0;
    virtual int get_response_status() const = 0;

    virtual void set_response_header(
      const std::string_view& name, const std::string_view& value) = 0;
    virtual void set_response_header(const std::string_view& name, size_t n)
    {
      set_response_header(name, std::to_string(n));
    }

    virtual void set_error(
      http_status status, const std::string& code, std::string&& msg)
    {
      set_error(ccf::ErrorDetails{status, code, std::move(msg)});
    }

    virtual void set_error(ccf::ErrorDetails&& error)
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg)}};
      // Set error_handler to replace, to avoid throwing if the error message
      // contains non-UTF8 characters. Other args are default values
      const auto s =
        body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
      set_response_status(error.status);
      set_response_body(std::vector<uint8_t>(s.begin(), s.end()));
      set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
    }

    /// Framework details
    virtual void set_apply_writes(bool apply) = 0;

    virtual void set_claims_digest(ccf::ClaimsDigest::Digest&& digest) = 0;
  };
}
