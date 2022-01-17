// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/claims_digest.h"
#include "ccf/tx_id.h"
#include "http/http_builder.h"
#include "http/http_consts.h"
#include "node/client_signatures.h"
#include "node/entities.h"
#include "node/node_info_network.h"
#include "node/rpc/error.h"

#include <llhttp/llhttp.h>
#include <variant>
#include <vector>

namespace ccf
{
  /*!
    Extension of llhttp_method
    to allow make_*_endpoint() to be a single uniform interface to define
    handlers for more than HTTP just verbs. Formerly used to allow WebSockets
    handlers, now removed. Kept for potential future extensions.

    This may be removed if instead of exposing a single RpcContext, callbacks
    are instead given a specialised *RpcContext, and make_endpoint becomes
    templated on Verb and specialised on the respective enum types.
  */
  class RESTVerb
  {
  private:
    int verb;

  public:
    RESTVerb() : verb(std::numeric_limits<int>::min()) {}
    RESTVerb(const llhttp_method& hm) : verb(hm) {}
    RESTVerb(const std::string& s)
    {
#define HTTP_METHOD_GEN(NUM, NAME, STRING) \
  if (s == #STRING) \
  { \
    verb = static_cast<llhttp_method>(NUM); \
    return; \
  }
      HTTP_METHOD_MAP(HTTP_METHOD_GEN)
#undef HTTP_METHOD_GEN
      throw std::logic_error(fmt::format("unknown method {}", s));
    }

    std::optional<llhttp_method> get_http_method() const
    {
      return static_cast<llhttp_method>(verb);
    }

    const char* c_str() const
    {
      return llhttp_method_name(static_cast<llhttp_method>(verb));
    }

    bool operator<(const RESTVerb& o) const
    {
      return verb < o.verb;
    }

    bool operator==(const RESTVerb& o) const
    {
      return verb == o.verb;
    }

    bool operator!=(const RESTVerb& o) const
    {
      return !(*this == o);
    }
  };

  // Custom to_json and from_json specializations which encode RESTVerb in a
  // lower-cased string, so it can be used in OpenAPI and similar documents
  inline void to_json(nlohmann::json& j, const RESTVerb& verb)
  {
    std::string s(verb.c_str());
    nonstd::to_lower(s);
    j = s;
  }

  inline void from_json(const nlohmann::json& j, RESTVerb& verb)
  {
    if (!j.is_string())
    {
      throw std::runtime_error(fmt::format(
        "Cannot parse RESTVerb from non-string JSON value: {}", j.dump()));
    }

    std::string s = j.get<std::string>();
    nonstd::to_upper(s);

    verb = RESTVerb(http::http_method_from_str(s.c_str()));
  }
}

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
