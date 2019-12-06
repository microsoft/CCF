// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rpc_tls_client.h"

#include <nlohmann/json.hpp>
#include <tls/keypair.h>

class SigJsonRpcTlsClient : public RpcTlsClient
{
private:
  tls::KeyPairPtr key_pair;

public:
  // Forward common arguments directly to base class
  template <typename... Ts>
  SigJsonRpcTlsClient(const tls::Pem& priv_key_, Ts&&... ts) :
    RpcTlsClient(ts...),
    key_pair(tls::make_key_pair(priv_key_))
  {}

  /** Generate sign and serialize transaction
   *
   * @param method Method name
   * @param params Method parameters
   *
   * @return signed serialized transaction
   */
  PreparedRpc gen_rpc(
    const std::string& method, const nlohmann::json& params) override
  {
    nlohmann::json j = RpcTlsClient::json_rpc(method, params);

    auto contents = nlohmann::json::to_msgpack(j);
    auto sig_contents = key_pair->sign(contents);

    nlohmann::json sj;
    sj["req"] = j;
    sj["sig"] = sig_contents;

    return gen_rpc_raw(sj, {j["id"]});
  }
};

class SigHttpRpcTlsClient : public HttpRpcTlsClient
{
private:
  tls::KeyPairPtr key_pair;

public:
  template <typename... Ts>
  SigHttpRpcTlsClient(const tls::Pem& priv_key_, Ts&&... ts) :
    HttpRpcTlsClient(ts...),
    key_pair(tls::make_key_pair(priv_key_))
  {}

  PreparedRpc gen_rpc(
    const std::string& method, const nlohmann::json& params) override
  {
    const auto body_j = json_rpc(method, params);
    const auto body_v = nlohmann::json::to_msgpack(body_j);
    auto r = enclave::http::Request(HTTP_POST);
    r.set_path(body_j["method"]);

    // TODO: Use httpsig.h, add signature header to this request

    const auto request = r.build_request(body_v);
    return {request, body_j["id"]};
  }
};

#ifdef HTTP
using SigRpcTlsClient = SigHttpRpcTlsClient;
#else
using SigRpcTlsClient = SigJsonRpcTlsClient;
#endif
