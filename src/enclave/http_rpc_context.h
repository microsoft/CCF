// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "httpparser.h"
#include "httpsig.h"
#include "rpccontext.h"

namespace enclave
{
  class HttpRpcContext : public RpcContext
  {
  private:
    nlohmann::json params = nlohmann::json::object();
    std::string entire_path = {};

  public:
    // TODO: This is a temporary bodge. Shouldn't be public?
    std::string_view remaining_path = {};

    HttpRpcContext(
      const SessionContext& s,
      http_method verb,
      const std::string_view& path,
      const std::string_view& query,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body,
      const std::vector<uint8_t>& raw_request_ = {},
      const std::vector<uint8_t>& raw_pbft = {}) :
      RpcContext(s, raw_request_, raw_pbft),
      entire_path(path)
    {
      remaining_path = entire_path;

      // Build a canonical serialization of this request. If the request is
      // signed, then all unsigned content must be removed
      auto canonical_headers = headers;
      const auto auth_it =
        canonical_headers.find(http::HTTP_HEADER_AUTHORIZATION);
      if (auth_it != canonical_headers.end())
      {
        std::string_view authz_header = auth_it->second;

        auto parsed_sign_params =
          http::HttpSignatureVerifier::parse_signature_params(authz_header);

        if (!parsed_sign_params.has_value())
        {
          throw std::logic_error(fmt::format(
            "Unable to parse signature params from: {}", authz_header));
        }

        // Keep all signed headers, and the auth header containing the signature
        // itself
        auto& signed_headers = parsed_sign_params->signed_headers;
        signed_headers.emplace_back(http::HTTP_HEADER_AUTHORIZATION);

        auto it = canonical_headers.begin();
        while (it != canonical_headers.end())
        {
          if (
            std::find(
              signed_headers.begin(), signed_headers.end(), it->first) ==
            signed_headers.end())
          {
            it = canonical_headers.erase(it);
          }
          else
          {
            ++it;
          }
        }
      }

      const auto canonical_request_header = fmt::format(
        "{} {} HTTP/1.1\r\n"
        "{}"
        "\r\n",
        http_method_str(verb),
        fmt::format("{}{}", path, query),
        enclave::http::get_header_string(canonical_headers));

      raw_request.resize(canonical_request_header.size() + body.size());
      ::memcpy(
        raw_request.data(),
        canonical_request_header.data(),
        canonical_request_header.size());
      ::memcpy(
        raw_request.data() + canonical_request_header.size(),
        body.data(),
        body.size());

      auto signed_req = http::HttpSignatureVerifier::parse(
        std::string(http_method_str(verb)), path, query, headers, body);
      if (signed_req.has_value())
      {
        signed_request = signed_req;
      }

      if (verb == HTTP_POST)
      {
        std::optional<jsonrpc::Pack> pack;

        if (body.empty())
        {
          params = nullptr;
        }
        else
        {
          auto [success, contents] = jsonrpc::unpack_rpc(body, pack);
          if (!success)
          {
            throw std::logic_error("Unable to unpack body.");
          }

          // Currently contents must either be a naked json payload, or a
          // JSON-RPC object. We don't check the latter object for validity, we
          // just extract its params field
          const auto params_it = contents.find(jsonrpc::PARAMS);
          if (params_it != contents.end())
          {
            params = *params_it;
          }
          else
          {
            params = contents;
          }

          const auto id_it = contents.find(jsonrpc::ID);
          if (id_it != contents.end())
          {
            request_index = *id_it;
          }
        }
      }
      else if (verb == HTTP_GET)
      {
        // TODO: Construct params by parsing query
      }
    }

    virtual const nlohmann::json& get_params() const override
    {
      return params;
    }

    virtual std::string get_method() const override
    {
      // Strip any leading /s
      return std::string(
        remaining_path.substr(remaining_path.find_first_not_of('/')));
    }

    virtual std::string get_whole_method() const override
    {
      return entire_path;
    }

    // TODO: These are still returning a JSON-RPC response body
    virtual std::vector<uint8_t> serialise_response() const override
    {
      nlohmann::json full_response;

      if (response_is_error())
      {
        const auto error = get_response_error();
        full_response = jsonrpc::error_response(
          get_request_index(), jsonrpc::Error(error->code, error->msg));
      }
      else
      {
        const auto payload = get_response_result();
        full_response = jsonrpc::result_response(get_request_index(), *payload);
      }

      for (const auto& [k, v] : headers)
      {
        const auto it = full_response.find(k);
        if (it == full_response.end())
        {
          full_response[k] = v;
        }
        else
        {
          LOG_DEBUG_FMT(
            "Ignoring response headers with key '{}' - already present in "
            "response object",
            k);
        }
      }

      const auto body = jsonrpc::pack(full_response, jsonrpc::Pack::Text);

      // We return status 200 regardless of whether the body contains a JSON-RPC
      // success or a JSON-RPC error
      auto http_response = http::Response(HTTP_STATUS_OK);
      return http_response.build_response(body);
    }

    virtual std::vector<uint8_t> result_response(
      const nlohmann::json& result) const override
    {
      auto http_response = http::Response(HTTP_STATUS_OK);
      return http_response.build_response(jsonrpc::pack(
        jsonrpc::result_response(get_request_index(), result),
        jsonrpc::Pack::Text));
    }

    std::vector<uint8_t> error_response(
      int error, const std::string& msg) const override
    {
      nlohmann::json error_element = jsonrpc::Error(error, msg);
      auto http_response = http::Response(HTTP_STATUS_OK);
      return http_response.build_response(jsonrpc::pack(
        jsonrpc::error_response(get_request_index(), error_element),
        jsonrpc::Pack::Text));
    }
  };

  inline std::shared_ptr<RpcContext> make_rpc_context(
    const SessionContext& s,
    const std::vector<uint8_t>& packed,
    const std::vector<uint8_t>& raw_pbft = {})
  {
    http::SimpleMsgProcessor processor;
    http::Parser parser(HTTP_REQUEST, processor);

    const auto parsed_count = parser.execute(packed.data(), packed.size());
    if (parsed_count != packed.size())
    {
      const auto err_no = (http_errno)parser.get_raw_parser()->http_errno;
      throw std::logic_error(fmt::format(
        "Failed to fully parse HTTP request. Parsed only {} bytes. Error code "
        "{} ({}: {})",
        parsed_count,
        err_no,
        http_errno_name(err_no),
        http_errno_description(err_no)));
    }

    if (processor.received.size() != 1)
    {
      throw std::logic_error(fmt::format(
        "Expected packed to contain a single complete HTTP message. Actually "
        "parsed {} messages",
        processor.received.size()));
    }

    const auto& msg = processor.received.front();

    return std::make_shared<HttpRpcContext>(
      s,
      msg.method,
      msg.path,
      msg.query,
      msg.headers,
      msg.body,
      packed,
      raw_pbft);
  }
}