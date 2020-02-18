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
    const auto body_v = jsonrpc::pack(body_j, jsonrpc::Pack::MsgPack);

    auto r = http::Request(body_j[jsonrpc::METHOD].get<std::string>());
    r.set_header(
      http::headers::CONTENT_TYPE, http::headervalues::contenttype::MSGPACK);

    r.set_body(&body_v);
    http::sign_request(r, key_pair);

    const auto request = r.build_request();

    return {request, body_j["id"]};
  }
};

using SigRpcTlsClient = SigHttpRpcTlsClient;