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
    uint64_t seq_no = {};
    nlohmann::json params = nlohmann::json::object();
    std::string entire_path = {};

  public:
    // TODO: This is a temporary bodge. Shouldn't be public?
    std::string_view remaining_path = {};

    HttpRpcContext(
      const SessionContext& s,
      http_method verb,
      const std::string& path,
      const std::string& query,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body,
      const std::vector<uint8_t>& raw = {},
      const std::vector<uint8_t>& raw_pbft = {}) :
      RpcContext(s, raw, raw_pbft),
      entire_path(path)
    {
      remaining_path = entire_path;

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
          seq_no, jsonrpc::Error(error->code, error->msg));
      }
      else
      {
        const auto payload = get_response_result();
        full_response = jsonrpc::result_response(seq_no, *payload);
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
        jsonrpc::result_response(seq_no, result), jsonrpc::Pack::Text));
    }

    std::vector<uint8_t> error_response(
      int error, const std::string& msg) const override
    {
      nlohmann::json error_element = jsonrpc::Error(error, msg);
      auto http_response = http::Response(HTTP_STATUS_OK);
      return http_response.build_response(jsonrpc::pack(
        jsonrpc::error_response(seq_no, error_element), jsonrpc::Pack::Text));
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