// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http/http_builder.h"
#include "http/http_consts.h"
#include "http/http_parser.h"
#include "http/ws_builder.h"
#include "http/ws_parser.h"
#include "node/rpc/serdes.h"
#include "tls_client.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
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
  ws::ResponseParser ws_parser;
  std::optional<std::string> prefix;
  tls::KeyPairPtr key_pair = nullptr;
  std::string key_id = "Invalid";
  bool is_ws = false;

  size_t next_send_id = 0;
  size_t next_recv_id = 0;

  std::vector<uint8_t> gen_ws_upgrade_request()
  {
    auto r = http::Request("/", HTTP_GET);
    r.set_header("Upgrade", "websocket");
    r.set_header("Connection", "Upgrade");
    r.set_header("Sec-WebSocket-Key", "iT9AbE3Q96TfyWZ+3gQdfg==");
    r.set_header("Sec-WebSocket-Version", "13");

    return r.build_request();
  }

  std::vector<uint8_t> gen_http_request_internal(
    const std::string& method,
    const CBuffer params,
    const std::string& content_type,
    llhttp_method verb)
  {
    auto path = method;
    if (prefix.has_value())
    {
      path = fmt::format("/{}/{}", prefix.value(), path);
    }

    auto r = http::Request(path, verb);
    r.set_body(params.p, params.n);
    r.set_header(http::headers::CONTENT_TYPE, content_type);

    if (key_pair != nullptr)
    {
      LOG_INFO_FMT("Signing HTTP request");
      http::sign_request(r, key_pair, key_id);
    }

    return r.build_request();
  }

  std::vector<uint8_t> gen_ws_request_internal(
    const std::string& method, const CBuffer params)
  {
    auto path = method;
    if (prefix.has_value())
    {
      path = fmt::format("/{}/{}", prefix.value(), path);
    }
    std::vector<uint8_t> body(params.p, params.p + params.n);
    return ws::make_in_frame(path, body);
  }

  std::vector<uint8_t> gen_request_internal(
    const std::string& method,
    const CBuffer params,
    const std::string& content_type,
    llhttp_method verb)
  {
    if (is_ws)
      return gen_ws_request_internal(method, params);
    else
      return gen_http_request_internal(method, params, content_type, verb);
  }

  Response call_raw(const std::vector<uint8_t>& raw)
  {
    CBuffer b(raw);
    write(b);
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
    key_id(key_id_),
    parser(*this),
    ws_parser(*this)
  {}

  HttpRpcTlsClient(const HttpRpcTlsClient& c) :
    TlsClient(c),
    key_id(c.key_id),
    parser(*this),
    ws_parser(*this)
  {}

  void upgrade_to_ws()
  {
    auto upgrade = gen_ws_upgrade_request();
    auto response = call_raw(upgrade);
    if (response.headers.find("sec-websocket-accept") == response.headers.end())
      throw std::logic_error("Failed to upgrade to websockets");
    is_ws = true;
  }

  void create_key_pair(const tls::Pem priv_key)
  {
    key_pair = tls::make_key_pair(priv_key);
  }

  PreparedRpc gen_request(
    const std::string& method,
    const CBuffer params,
    const std::string& content_type,
    llhttp_method verb = HTTP_POST)
  {
    return {gen_request_internal(method, params, content_type, verb),
            next_send_id++};
  }

  PreparedRpc gen_request(
    const std::string& method,
    const nlohmann::json& params = nullptr,
    llhttp_method verb = HTTP_POST)
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
      verb);
  }

  Response call(
    const std::string& method,
    const nlohmann::json& params = nullptr,
    llhttp_method verb = HTTP_POST)
  {
    return call_raw(gen_request(method, params, verb));
  }

  Response call(
    const std::string& method,
    const CBuffer& params,
    llhttp_method verb = HTTP_POST)
  {
    return call_raw(
      gen_request(method, params, http::headervalues::contenttype::JSON, verb));
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
      const auto& content_type = resp.headers.find(http::headers::CONTENT_TYPE);
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
      if (is_ws)
      {
        auto buf = read(ws::INITIAL_READ);
        size_t n = ws_parser.consume(buf.data(), buf.size());
        buf = read(n);
        n = ws_parser.consume(buf.data(), buf.size());
        assert(n == ws::INITIAL_READ);
      }
      else
      {
        const auto next = read_all();
        parser.execute(next.data(), next.size());
      }
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