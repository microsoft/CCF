// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/http_consts.h"
#include "ccf/serdes.h"
#include "http/http_builder.h"
#include "http/http_parser.h"
#include "tls_client.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <http/http_sig.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <thread>

namespace client
{
  class HttpRpcTlsClient : public TlsClient, public http::ResponseProcessor
  {
  public:
    struct PreparedRpc
    {
      std::vector<uint8_t> encoded;
      size_t id;
    };

    struct Response
    {
      size_t id;
      http_status status;
      http::HeaderMap headers;
      std::vector<uint8_t> body;
    };

  protected:
    http::ResponseParser parser;
    std::optional<std::string> prefix;
    crypto::KeyPairPtr key_pair = nullptr;
    std::string key_id = "Invalid";

    size_t next_send_id = 0;
    size_t next_recv_id = 0;

    std::vector<uint8_t> gen_http_request_internal(
      const std::string& method,
      const std::span<const uint8_t> params,
      const std::string& content_type,
      llhttp_method verb,
      const char* auth_token = nullptr)
    {
      auto path = method;
      if (prefix.has_value())
      {
        path = fmt::format("/{}/{}", prefix.value(), path);
      }

      auto r = http::Request(path, verb);
      r.set_body(params.data(), params.size());
      r.set_header(http::headers::CONTENT_TYPE, content_type);
      r.set_header("Host", host);
      if (auth_token != nullptr)
      {
        r.set_header(
          http::headers::AUTHORIZATION, fmt::format("Bearer {}", auth_token));
      }

      if (key_pair != nullptr)
      {
        http::sign_request(r, key_pair, key_id);
      }

      return r.build_request();
    }

    std::vector<uint8_t> gen_request_internal(
      const std::string& method,
      const std::span<const uint8_t> params,
      const std::string& content_type,
      llhttp_method verb,
      const char* auth_token = nullptr)
    {
      return gen_http_request_internal(
        method, params, content_type, verb, auth_token);
    }

    Response call_raw(const std::vector<uint8_t>& raw)
    {
      write(raw);
      return read_response();
    }

    Response call_raw(const PreparedRpc& prep)
    {
      return call_raw(prep.encoded);
    }

    std::optional<Response> last_response;

  public:
    using TlsClient::TlsClient;

    HttpRpcTlsClient(
      const std::string& host,
      const std::string& port,
      std::shared_ptr<tls::CA> node_ca = nullptr,
      std::shared_ptr<tls::Cert> cert = nullptr,
      const std::string& key_id_ = "Invalid") :
      TlsClient(host, port, node_ca, cert),
      parser(*this),
      key_id(key_id_)
    {}

    HttpRpcTlsClient(const HttpRpcTlsClient& c) :
      TlsClient(c),
      parser(*this),
      key_id(c.key_id)
    {}

    void create_key_pair(const crypto::Pem priv_key)
    {
      key_pair = crypto::make_key_pair(priv_key);
    }

    PreparedRpc gen_request(
      const std::string& method,
      const std::span<const uint8_t> params,
      const std::string& content_type,
      llhttp_method verb = HTTP_POST,
      const char* auth_token = nullptr)
    {
      return {
        gen_request_internal(method, params, content_type, verb, auth_token),
        next_send_id++};
    }

    PreparedRpc gen_request(
      const std::string& method,
      const nlohmann::json& params = nullptr,
      llhttp_method verb = HTTP_POST,
      const char* auth_token = nullptr)
    {
      std::vector<uint8_t> body;
      if (!params.is_null())
      {
        body = serdes::pack(params, serdes::Pack::MsgPack);
      }
      return gen_request(
        method,
        {body.data(), body.size()},
        http::headervalues::contenttype::MSGPACK,
        verb,
        auth_token);
    }

    Response call(
      const std::string& method,
      const nlohmann::json& params = nullptr,
      llhttp_method verb = HTTP_POST)
    {
      return call_raw(gen_request(method, params, verb, nullptr));
    }

    Response call(
      const std::string& method,
      const std::span<const uint8_t> params,
      llhttp_method verb = HTTP_POST)
    {
      return call_raw(gen_request(
        method, params, http::headervalues::contenttype::JSON, verb));
    }

    Response post(const std::string& method, const nlohmann::json& params)
    {
      return call(method, params, HTTP_POST);
    }

    Response get(
      const std::string& method, const nlohmann::json& params = nullptr)
    {
      // GET body is ignored, so params must be placed in query
      auto full_path = method;
      if (!params.is_null())
      {
        for (auto it = params.begin(); it != params.end(); ++it)
        {
          full_path += fmt::format(
            "{}{}={}",
            it == params.begin() ? "?" : "&",
            it.key(),
            it.value().is_string() ? it.value().get<std::string>() :
                                     it.value().dump());
        }
      }
      return call(full_path, nullptr, HTTP_GET);
    }

    nlohmann::json unpack_body(const Response& resp)
    {
      if (resp.body.empty())
      {
        return nullptr;
      }
      else if (http::status_success(resp.status))
      {
        const auto& content_type =
          resp.headers.find(http::headers::CONTENT_TYPE);
        return serdes::unpack(resp.body, serdes::Pack::MsgPack);
      }
      else
      {
        return std::string(resp.body.begin(), resp.body.end());
      }
    }

    std::string get_error(const Response& resp)
    {
      return std::string(resp.body.begin(), resp.body.end());
    }

    Response read_response()
    {
      last_response = std::nullopt;

      while (!last_response.has_value())
      {
        const auto next = read_all();
        parser.execute(next.data(), next.size());
      }

      return std::move(last_response.value());
    }

    std::vector<uint8_t> read_raw_response()
    {
      std::vector<uint8_t> next;
      last_response = std::nullopt;
      while (!last_response.has_value())
      {
        next = read_all();
        parser.execute(next.data(), next.size());
      }
      return next;
    }

    std::optional<Response> read_response_non_blocking()
    {
      if (bytes_available())
      {
        return read_response();
      }

      return std::nullopt;
    }

    virtual void handle_response(
      http_status status,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      last_response = {
        next_recv_id++, status, std::move(headers), std::move(body)};
    }

    void set_prefix(const std::string& prefix_)
    {
      prefix = prefix_;
    }
  };

  using RpcTlsClient = HttpRpcTlsClient;
}
