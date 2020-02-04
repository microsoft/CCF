// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rpc_tls_client.h"

#include <enclave/httpsig.h>
#include <nlohmann/json.hpp>
#include <tls/base64.h>
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
    auto sig_raw = key_pair->sign(contents);

    nlohmann::json sj;
    sj["req"] = j;
    sj["sig"] = sig_raw;

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

    // TODO: This currently fails to verify - investigate why
    // NB: This is not a particularly interesting signature, just a minimal PoC.
    // Expect most HTTP authorization signing to be done by existing
    // libraries/clients
    tls::HashBytes body_digest;
    tls::do_hash(body_v.data(), body_v.size(), body_digest, MBEDTLS_MD_SHA256);
    const auto digest_value = fmt::format(
      "{}={}",
      "SHA-256",
      tls::b64_from_raw(body_digest.data(), body_digest.size()));
    r.set_header("digest", digest_value);

    auto headers = r.get_headers();
    headers["content-length"] = fmt::format("{}", body_v.size());

    std::vector<std::string_view> headers_to_sign;
    for (const auto& [k, v] : headers)
    {
      headers_to_sign.emplace_back(k);
    }

    std::string query = "";
    const auto signing_string = enclave::http::construct_raw_signed_string(
      http_method_str(HTTP_POST), method, query, headers, headers_to_sign);
    if (!signing_string.has_value())
    {
      throw std::logic_error(fmt::format("Error constructing signed string"));
    }

    const auto sig_raw = key_pair->sign(signing_string.value());

    auto auth_value = fmt::format(
      "Signature "
      "keyId=\"ignored\",algorithm=\"ecdsa-sha256\",headers=\"{}\",signature="
      "\"{}\"",
      fmt::format("{}", fmt::join(headers_to_sign, " ")),
      tls::b64_from_raw(sig_raw.data(), sig_raw.size()));
    r.set_header("authorization", auth_value);

    const auto request = r.build_request(body_v);
    return {request, body_j["id"]};
  }
};

using SigRpcTlsClient = SigHttpRpcTlsClient;