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

  PreparedRpc gen_request(
    const std::string& method, const nlohmann::json& params) override
  {
    auto r = gen_request_internal(method, params);
    http::sign_request(r, key_pair);
    return {r.build_request(), next_send_id++};
  }
};

using SigRpcTlsClient = SigHttpRpcTlsClient;