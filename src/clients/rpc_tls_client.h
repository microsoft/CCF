// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls_client.h"

#include <nlohmann/json.hpp>
#include <optional>

class RpcTlsClient : public TlsClient
{
public:
  uint32_t id = 0;

  struct PreparedRpc
  {
    std::vector<uint8_t> encoded;
    size_t id;
  };

  using TlsClient::TlsClient;

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
    const std::string& method, const nlohmann::json& params)
  {
    return gen_rpc_raw(json_rpc(method, params));
  }

  virtual PreparedRpc gen_rpc(const std::string& method)
  {
    return gen_rpc_raw(json_rpc(method, nlohmann::json::array()));
  }

  nlohmann::json json_rpc(
    const std::string& method, const nlohmann::json& params)
  {
    nlohmann::json j;
    j["jsonrpc"] = "2.0";
    j["id"] = id++;
    j["method"] = method;
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
    return call(method, nlohmann::json::array());
  }

  std::vector<uint8_t> read_rpc()
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
};
