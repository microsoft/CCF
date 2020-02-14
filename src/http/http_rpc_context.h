// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpccontext.h"
#include "http_parser.h"
#include "http_sig.h"

namespace http
{
  static constexpr auto CONTENT_TYPE_JSON = "application/json";
  static constexpr auto CONTENT_TYPE_MSGPACK = "application/msgpack";

  class HttpRpcContext : public enclave::RpcContext
  {
  private:
    http_method verb;
    std::vector<uint8_t> request_body;
    std::string path = {};

    http::HeaderMap request_headers;

    mutable jsonrpc::Pack body_packing = jsonrpc::Pack::Text;

  public:
    HttpRpcContext(
      const enclave::SessionContext& s,
      http_method verb_,
      const std::string_view& path_,
      const std::string_view& query_,
      const http::HeaderMap& headers_,
      const std::vector<uint8_t>& body_,
      const std::vector<uint8_t>& raw_request_ = {},
      const std::vector<uint8_t>& raw_pbft_ = {}) :
      RpcContext(s, raw_request_, raw_pbft_),
      verb(verb_),
      path(path_),
      request_body(body_)
    {
      // Build a canonical serialization of this request. If the request is
      // signed, then all unsigned headers must be removed
      request_headers = headers_;
      const auto auth_it =
        request_headers.find(http::HTTP_HEADER_AUTHORIZATION);
      if (auth_it != request_headers.end())
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

        for (const auto& required_header :
             {http::HTTP_HEADER_DIGEST, http::SIGN_HEADER_REQUEST_TARGET})
        {
          if (
            std::find(
              signed_headers.begin(), signed_headers.end(), required_header) ==
            signed_headers.end())
          {
            throw std::logic_error(fmt::format(
              "HTTP authorization header must sign header '{}'",
              required_header));
          }
        }

        auto it = request_headers.begin();
        while (it != request_headers.end())
        {
          if (
            std::find(
              signed_headers.begin(), signed_headers.end(), it->first) ==
            signed_headers.end())
          {
            it = request_headers.erase(it);
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
        fmt::format("{}{}", path_, query_),
        http::get_header_string(request_headers));

      raw_request.resize(canonical_request_header.size() + request_body.size());
      ::memcpy(
        raw_request.data(),
        canonical_request_header.data(),
        canonical_request_header.size());
      ::memcpy(
        raw_request.data() + canonical_request_header.size(),
        request_body.data(),
        request_body.size());

      auto signed_req = http::HttpSignatureVerifier::parse(
        std::string(http_method_str(verb)),
        path_,
        query_,
        headers_,
        request_body);
      if (signed_req.has_value())
      {
        signed_request = signed_req;
      }

      // TODO: YUCK! This sets request_index, so we need to call it!
      get_params();
    }

    virtual const std::vector<uint8_t>& get_request_body() const override
    {
      return request_body;
    }

    virtual nlohmann::json get_params() const override
    {
      nlohmann::json params;

      if (verb == HTTP_POST)
      {
        const auto content_type_it =
          request_headers.find(HTTP_HEADER_CONTENT_TYPE);
        if (content_type_it != request_headers.end())
        {
          const auto& content_type = content_type_it->second;
          if (content_type == CONTENT_TYPE_JSON)
          {
            body_packing = jsonrpc::Pack::Text;
          }
          else if (content_type == CONTENT_TYPE_MSGPACK)
          {
            body_packing = jsonrpc::Pack::MsgPack;
          }
          else
          {
            throw std::logic_error(fmt::format(
              "Unsupported content type {}. Only {} and {} are currently "
              "supported",
              content_type,
              CONTENT_TYPE_JSON,
              CONTENT_TYPE_MSGPACK));
          }
        }
        else
        {
          const auto pack = jsonrpc::detect_pack(request_body);

          if (pack.has_value())
          {
            body_packing = pack.value();
          }
        }

        if (request_body.empty())
        {
          params = nullptr;
        }
        else
        {
          const auto contents = jsonrpc::unpack(request_body, body_packing);

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
      else
      {
        throw std::logic_error(
          "The only HTTP verb currently supported is POST");
      }

      return params;
    }

    virtual std::string get_method() const override
    {
      return path;
    }

    virtual void set_method(const std::string_view& p) override
    {
      path = p;
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

      for (const auto& [k, v] : response_headers)
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

      const auto body = jsonrpc::pack(full_response, body_packing);

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
        jsonrpc::result_response(get_request_index(), result), body_packing));
    }

    std::vector<uint8_t> error_response(
      int error, const std::string& msg) const override
    {
      nlohmann::json error_element = jsonrpc::Error(error, msg);
      auto http_response = http::Response(HTTP_STATUS_OK);
      return http_response.build_response(jsonrpc::pack(
        jsonrpc::error_response(get_request_index(), error_element),
        body_packing));
    }
  };
}

// TODO: This is very ugly. Should make an rpc:: folder+namespace?
namespace enclave
{
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

    return std::make_shared<http::HttpRpcContext>(
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