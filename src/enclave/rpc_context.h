// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/claims_digest.h"
#include "ccf/rest_verb.h"
#include "ccf/service/signed_req.h"
#include "ccf/tx_id.h"
#include "http/http_builder.h"
#include "ccf/http_consts.h"
#include "node/entities.h"
#include "node/rpc/error.h"
#include "service/tables/node_info_network.h"

#include <variant>
#include <vector>

namespace enclave
{
  static constexpr size_t InvalidSessionId = std::numeric_limits<size_t>::max();
  using ListenInterfaceID = ccf::NodeInfoNetwork::RpcInterfaceID;

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
    std::shared_ptr<SessionContext> session;

    virtual FrameFormat frame_format() const = 0;

    // raw bft Request
    std::vector<uint8_t> bft_raw = {};

    bool is_create_request = false;
    bool execute_on_node = false;

    ccf::ClaimsDigest claims;

    RpcContext(std::shared_ptr<SessionContext> s) : session(s) {}

    RpcContext(
      std::shared_ptr<SessionContext> s, const std::vector<uint8_t>& bft_raw_) :
      session(s),
      bft_raw(bft_raw_)
    {}

    virtual ~RpcContext() {}

    /// Request details
    virtual size_t get_request_index() const = 0;

    virtual const std::vector<uint8_t>& get_request_body() const = 0;
    virtual const std::string& get_request_query() const = 0;
    virtual PathParams& get_request_path_params() = 0;
    virtual const ccf::RESTVerb& get_request_verb() const = 0;
    virtual std::string get_request_path() const = 0;

    virtual std::string get_method() const = 0;
    virtual void set_method(const std::string_view& method) = 0;

    virtual const http::HeaderMap& get_request_headers() const = 0;
    virtual std::optional<std::string> get_request_header(
      const std::string_view& name) = 0;

    virtual const std::vector<uint8_t>& get_serialised_request() = 0;
    virtual const std::string& get_request_url() const = 0;

    /// Response details
    virtual void set_response_body(const std::vector<uint8_t>& body) = 0;
    virtual void set_response_body(std::vector<uint8_t>&& body) = 0;
    virtual void set_response_body(std::string&& body) = 0;

    virtual void set_response_status(int status) = 0;
    virtual int get_response_status() const = 0;

    virtual void set_tx_id(const ccf::TxID& tx_id) = 0;

    virtual void set_response_header(
      const std::string_view& name, const std::string_view& value) = 0;
    virtual void set_response_header(const std::string_view& name, size_t n)
    {
      set_response_header(name, fmt::format("{}", n));
    }

    virtual void set_error(
      http_status status, const std::string& code, std::string&& msg)
    {
      set_error({status, code, std::move(msg)});
    }

    virtual void set_error(ccf::ErrorDetails&& error)
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg)}};
      const auto s = body.dump();
      set_response_status(error.status);
      set_response_body(std::vector<uint8_t>(s.begin(), s.end()));
      set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
    }

    virtual void set_apply_writes(bool apply) = 0;
    virtual bool should_apply_writes() const = 0;

    virtual void reset_response() = 0;

    virtual std::vector<uint8_t> serialise_response() const = 0;

    virtual void set_claims_digest(ccf::ClaimsDigest::Digest&& digest)
    {
      claims.set(std::move(digest));
    }
  };
}
