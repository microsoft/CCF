// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http/http_builder.h"
#include "http/http_consts.h"
#include "http/http_parser.h"
#include "node/rpc/json_rpc.h"
#include "tls_client.h"

#include <fmt/format_header_only.h>
#include <http/http_sig.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <thread>
#include <tls/key_pair.h>

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

  size_t next_send_id = 0;
  size_t next_recv_id = 0;

  std::vector<uint8_t> gen_request_internal(
    const std::string& method,
    const CBuffer params,
    tls::KeyPairPtr kp = nullptr,
    const std::string& content_type = http::headervalues::contenttype::MSGPACK)
  {
    auto path = method;
    if (prefix.has_value())
    {
      path = fmt::format("/{}/{}", prefix.value(), path);
    }

    auto r = http::Request(path);
    r.set_body(params.p, params.n);
    r.set_header(http::headers::CONTENT_TYPE, content_type);

    if (kp != nullptr)
    {
      http::sign_request(r, kp);
    }

    return r.build_request();
  }

  Response call_raw(const std::vector<uint8_t>& raw)
  {
    CBuffer b(raw);
    write(b);
    return read_response();
  }

  std::optional<Response> last_response;

public:
  using TlsClient::TlsClient;

  HttpRpcTlsClient(
    const std::string& host,
    const std::string& port,
    std::shared_ptr<tls::CA> node_ca = nullptr,
    std::shared_ptr<tls::Cert> cert = nullptr) :
    TlsClient(host, port, node_ca, cert),
    parser(*this)
  {}

  virtual PreparedRpc gen_request(
    const std::string& method,
    const CBuffer params,
    const std::string& content_type = http::headervalues::contenttype::MSGPACK)
  {
    return {gen_request_internal(method, params, nullptr, content_type),
            next_send_id++};
  }

  virtual PreparedRpc gen_request(
    const std::string& method, const nlohmann::json& params = nullptr)
  {
    auto p = jsonrpc::pack(params, jsonrpc::Pack::MsgPack);
    return gen_request(method, {p.data(), p.size()});
  }

  Response call(
    const std::string& method, const nlohmann::json& params = nullptr)
  {
    return call_raw(gen_request(method, params).encoded);
  }

  Response call(const std::string& method, const CBuffer params)
  {
    return call_raw(
      gen_request(method, params, http::headervalues::contenttype::OCTET_STREAM)
        .encoded);
  }

  nlohmann::json unpack_body(const Response& resp)
  {
    if (resp.body.empty())
    {
      return nullptr;
    }
    else if (http::status_ok(resp.status))
    {
      const auto& content_type = resp.headers.find(http::headers::CONTENT_TYPE);
      return jsonrpc::unpack(resp.body, jsonrpc::Pack::MsgPack);
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