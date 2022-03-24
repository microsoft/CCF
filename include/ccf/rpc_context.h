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

    // Only set in the case of a forwarded RPC
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

  /// Describes the currently executing RPC.
  class RpcContext
  {
  public:
    virtual ~RpcContext() = default;

    /// @name Access request
    /// Methods to access fields of the received request. Describes fields
    /// parsed from HTTP, but aims to generalise across other request protocols.
    ///@{

    /// Return information about the persistent session which this request was
    /// received on. Allows correlation between multiple requests coming from
    /// the same long-lived session.
    virtual std::shared_ptr<SessionContext> get_session_context() const = 0;

    virtual const std::vector<uint8_t>& get_request_body() const = 0;
    virtual const std::string& get_request_query() const = 0;
    virtual const ccf::RESTVerb& get_request_verb() const = 0;
    virtual std::string get_request_path() const = 0;
    virtual std::string get_method() const = 0;

    /// Returns a map of all PathParams parsed out of the original query path.
    /// For instance if this endpoint was installed at `/foo/{name}/{age}`, and
    /// the request path `/foo/bob/42`, this would return the map:
    /// {"name": "bob", "age": "42"}
    virtual const PathParams& get_request_path_params() = 0;

    /// Returns map of all headers found in the request.
    virtual const http::HeaderMap& get_request_headers() const = 0;

    /// Returns value associated with named header, or nullopt of this header
    /// was not present.
    virtual std::optional<std::string> get_request_header(
      const std::string_view& name) = 0;

    /// Returns full URL provided in request, rather than split into path +
    /// query.
    virtual const std::string& get_request_url() const = 0;

    /// Returns frame format describing the protocol that the request was
    /// received over.
    virtual ccf::FrameFormat frame_format() const = 0;
    ///@}

    /// @name Construct response
    /// Methods to set sections of response, which will be serialised and
    /// transmitted to client.
    ///@{

    /// Sets the main body or payload of the response.
    virtual void set_response_body(const std::vector<uint8_t>& body) = 0;
    /// Sets the main body or payload of the response.
    virtual void set_response_body(std::vector<uint8_t>&& body) = 0;
    /// Sets the main body or payload of the response.
    virtual void set_response_body(std::string&& body) = 0;

    /// Sets initial status code summarising result of RPC.
    virtual void set_response_status(int status) = 0;
    virtual int get_response_status() const = 0;

    virtual void set_response_header(
      const std::string_view& name, const std::string_view& value) = 0;
    virtual void set_response_header(const std::string_view& name, size_t n)
    {
      set_response_header(name, std::to_string(n));
    }

    /// Construct OData-formatted error response.
    virtual void set_error(
      http_status status, const std::string& code, std::string&& msg)
    {
      set_error(ccf::ErrorDetails{status, code, std::move(msg)});
    }

    /// Construct OData-formatted error response.
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
    ///@}

    /// @name Framework metadata
    /// Methods which affect how the framework processes this transaction.
    ///@{

    /// Tells the framework to apply or not apply this transaction.
    /// By default that decision is based on the response status, with successes
    /// applied and errors producing no persistent writes. This value will
    /// override, allowing changes to be persisted/dropped regardless of
    /// response type.
    virtual void set_apply_writes(bool apply) = 0;

    /// Sets the application claims digest associated with this transaction.
    /// This digest is used to construct the Merkle tree leaf representing this
    /// transaction. This allows a transaction to make specific,
    /// separately-revealable claims in each transaction, without being bound to
    /// the transaction serialisation format or what is stored in the KV.
    /// The digest will be included in receipts issued for that transaction.
    virtual void set_claims_digest(ccf::ClaimsDigest::Digest&& digest) = 0;
    ///@}
  };
}
