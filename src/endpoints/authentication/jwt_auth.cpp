// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/jwt_auth.h"

#include "ccf/rpc_context.h"
#include "ccf/service/tables/jwt.h"
#include "enclave/enclave_time.h"
#include "http/http_jwt.h"

namespace ccf
{
  std::unique_ptr<AuthnIdentity> JwtAuthnPolicy::authenticate(
    kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& headers = ctx->get_request_headers();

    const auto token_opt =
      http::JwtVerifier::extract_token(headers, error_reason);

    if (token_opt.has_value())
    {
      auto& token = token_opt.value();
      auto keys =
        tx.ro<JwtPublicSigningKeys>(ccf::Tables::JWT_PUBLIC_SIGNING_KEYS);
      auto key_issuers = tx.ro<JwtPublicSigningKeyIssuer>(
        ccf::Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER);
      const auto key_id = token.header_typed.kid;
      const auto token_key = keys->get(key_id);
      if (!token_key.has_value())
      {
        error_reason = "JWT signing key not found";
      }
      else if (!http::JwtVerifier::validate_token_signature(
                 token, token_key.value()))
      {
        error_reason = "JWT signature is invalid";
      }
      else
      {
        // Check that the Not Before and Expiration Time claims are valid
        const size_t time_now =
          std::chrono::duration_cast<std::chrono::seconds>(
            ccf::get_enclave_time())
            .count();
        if (time_now < token.payload_typed.nbf)
        {
          error_reason = fmt::format(
            "Current time {} is before token's Not Before (nbf) claim {}",
            time_now,
            token.payload_typed.nbf);
        }
        else if (time_now > token.payload_typed.exp)
        {
          error_reason = fmt::format(
            "Current time {} is after token's Expiration Time (exp) claim {}",
            time_now,
            token.payload_typed.exp);
        }
        else
        {
          auto identity = std::make_unique<JwtAuthnIdentity>();
          identity->key_issuer = key_issuers->get(key_id).value();
          identity->header = std::move(token.header);
          identity->payload = std::move(token.payload);
          return identity;
        }
      }
    }

    return nullptr;
  }

  void JwtAuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
  {
    ctx->set_error(
      HTTP_STATUS_UNAUTHORIZED,
      ccf::errors::InvalidAuthenticationInfo,
      std::move(error_reason));
    ctx->set_response_header(
      http::headers::WWW_AUTHENTICATE,
      "Bearer realm=\"JWT bearer token access\", error=\"invalid_token\"");
  }

  const OpenAPISecuritySchema JwtAuthnPolicy::security_schema = std::make_pair(
    JwtAuthnPolicy::SECURITY_SCHEME_NAME,
    nlohmann::json{
      {"type", "http"}, {"scheme", "bearer"}, {"bearerFormat", "JWT"}});
}
