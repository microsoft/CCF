// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rpc_tls_client.h"

#include <http/http_sig.h>
#include <nlohmann/json.hpp>
#include <tls/base64.h>
#include <tls/keypair.h>

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
    const auto body_v = jsonrpc::pack(body_j, jsonrpc::Pack::Text);

    auto r = http::Request(body_j[jsonrpc::METHOD].get<std::string>());
    r.set_header("content-type", "application/json");
    http::sign_request(r, body_v, key_pair);

    const auto request = r.build_request(body_v);

    return {request, body_j["id"]};
  }
};

using SigRpcTlsClient = SigHttpRpcTlsClient;