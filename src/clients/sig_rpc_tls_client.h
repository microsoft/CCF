// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rpc_tls_client.h"

#include <nlohmann/json.hpp>
#include <tls/base64.h>

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

  PreparedRpc gen_request(
    const std::string& method, const CBuffer params,
    const std::string& content_type = http::headervalues::contenttype::MSGPACK) override
  {
    return {gen_request_internal(method, params, key_pair, content_type),
            next_send_id++};
  }

  PreparedRpc gen_request(
    const std::string& method, const nlohmann::json& params) override
  {
    auto p = jsonrpc::pack(params, jsonrpc::Pack::MsgPack);
    return gen_request(method, {p.data(), p.size()});
  }
};

using SigRpcTlsClient = SigHttpRpcTlsClient;