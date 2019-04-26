// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rpc_tls_client.h"

#include <nlohmann/json.hpp>
#include <tls/keypair.h>

class SigRpcTlsClient : public RpcTlsClient
{
private:
  tls::KeyPair key_pair;

public:
  // Forward common arguments directly to base class
  template <typename... Ts>
  SigRpcTlsClient(const std::vector<uint8_t>& priv_key_, Ts&&... ts) :
    RpcTlsClient(ts...),
    key_pair(priv_key_)
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
    auto sig_contents = key_pair.sign(contents);

    nlohmann::json sj;
    sj["req"] = j;
    sj["sig"] = sig_contents;
    return gen_rpc_raw(sj, {j["id"]});
  }
};