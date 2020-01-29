// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/httpbuilder.h"
#include "enclave/httpparser.h"
#include "tls_client.h"

#include <fmt/format_header_only.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <thread>

class JsonRpcTlsClient : public TlsClient
{
public:
  uint32_t id = 0;
  std::optional<std::string> prefix;

  struct PreparedRpc
  {
    std::vector<uint8_t> encoded;
    size_t id;
  };

  using TlsClient::TlsClient;

  JsonRpcTlsClient(
    const std::string& host,
    const std::string& port,
    std::shared_ptr<tls::CA> node_ca = nullptr,
    std::shared_ptr<tls::Cert> cert = nullptr) :
    TlsClient(host, port, node_ca, cert)
  {}

  PreparedRpc gen_rpc_raw(
    const nlohmann::json& j, const std::optional<size_t>& explicit_id = {})
  {
    auto m = nlohmann::json::to_msgpack(j);
    auto len = static_cast<const uint32_t>(m.size());
    std::vector<uint8_t> r(len + sizeof(len));
    std::copy(m.cbegin(), m.cend(), r.begin() + sizeof(len));
    auto plen = reinterpret_cast<const uint8_t*>(&len);
    std::copy(plen, plen + sizeof(len), r.begin());
    return {
      r, explicit_id.has_value() ? explicit_id.value() : j["id"].get<size_t>()};
  }

  /** Generate and serialize transaction
   *
   * This is useful when preparing transactions ahead of time for later sending.
   *
   * @param method Method name
   * @param params Method parameters
   *
   * @return serialized transaction
   */
  virtual PreparedRpc gen_rpc(
    const std::string& method,
    const nlohmann::json& params = nlohmann::json::array())
  {
    return gen_rpc_raw(json_rpc(method, params));
  }

  nlohmann::json json_rpc(
    const std::string& method, const nlohmann::json& params)
  {
    auto method_ = method;
    if (prefix.has_value())
    {
      method_ = fmt::format("{}/{}", prefix.value(), method);
    }

    nlohmann::json j;
    j["jsonrpc"] = "2.0";
    j["id"] = id++;
    j["method"] = method_;
    j["params"] = params;
    return j;
  }

  std::vector<uint8_t> call_raw(const std::vector<uint8_t>& raw)
  {
    CBuffer b(raw);
    write(b);
    return read_rpc();
  }

  /** Call method with parameters
   *
   * @param method Method name
   * @param params Parameters to the method
   *
   * @return serialized response, can be parsed with
   * nlohmann::json::from_msgpack
   */
  std::vector<uint8_t> call(
    const std::string& method, const nlohmann::json& params)
  {
    return call_raw(gen_rpc(method, params).encoded);
  }

  /** Call method
   *
   * @param method Method name
   *
   * @return serialized response, can be parsed with
   * nlohmann::json::from_msgpack
   */
  std::vector<uint8_t> call(const std::string& method)
  {
    return call(method, nlohmann::json::object());
  }

  virtual std::vector<uint8_t> read_rpc()
  {
    // read len
    uint32_t len;
    read({reinterpret_cast<uint8_t*>(&len), sizeof(len)});
    std::vector<uint8_t> r(len);
    read(r);
    return r;
  }

  std::optional<std::vector<uint8_t>> read_rpc_non_blocking()
  {
    // read len
    uint32_t len;
    if (!read_non_blocking({reinterpret_cast<uint8_t*>(&len), sizeof(len)}))
      return {};
    // read payload
    std::vector<uint8_t> r(len);
    read(r);
    return r;
  }

  void set_prefix(const std::string& prefix_)
  {
    prefix = prefix_;
  }
};

class HttpRpcTlsClient : public JsonRpcTlsClient,
                         public enclave::http::MsgProcessor
{
  enclave::http::Parser parser;
  std::vector<uint8_t> message_body;

public:
  HttpRpcTlsClient(
    const std::string& host,
    const std::string& port,
    std::shared_ptr<tls::CA> node_ca = nullptr,
    std::shared_ptr<tls::Cert> cert = nullptr) :
    JsonRpcTlsClient(host, port, node_ca, cert),
    parser(HTTP_RESPONSE, *this)
  {}

  virtual PreparedRpc gen_rpc(
    const std::string& method,
    const nlohmann::json& params = nlohmann::json::array()) override
  {
    const auto body_j = json_rpc(method, params);
    const auto body_v = nlohmann::json::to_msgpack(body_j);
    auto r = enclave::http::Request(HTTP_POST);
    r.set_path(body_j["method"]);
    const auto request = r.build_request(body_v);
    return {request, body_j["id"]};
  }

  virtual std::vector<uint8_t> read_rpc() override
  {
    message_body.clear();

    while (message_body.empty())
    {
      const auto next = read_all();
      parser.execute(next.data(), next.size());
    }

    return message_body;
  }

  virtual void handle_message(
    http_method method,
    const std::string& path,
    const std::string& query,
    const enclave::http::HeaderMap& headers,
    const std::vector<uint8_t>& body) override
  {
    message_body = body;
  }
};

#ifndef FTCP
using RpcTlsClient = HttpRpcTlsClient;
#else
using RpcTlsClient = JsonRpcTlsClient;
#endif
