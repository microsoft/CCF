// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"
#include "http/http_jwt.h"
#include "node/jwt.h"

namespace ccf
{
  struct JwtAuthnIdentity : public AuthnIdentity
  {
    std::string key_issuer;
    nlohmann::json header;
    nlohmann::json payload;
  };

  class JwtAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;

  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto& headers = ctx->get_request_headers();

      const auto token =
        http::JwtVerifier::extract_token(headers, error_reason);

      if (token.has_value())
      {
        auto keys_view = tx.get_read_only_view<JwtPublicSigningKeys>(
          ccf::Tables::JWT_PUBLIC_SIGNING_KEYS);
        auto key_issuer_view = tx.get_read_only_view<JwtPublicSigningKeyIssuer>(
          ccf::Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER);
        const auto key_id = token.value().header_typed.kid;
        const auto token_key = keys_view->get(key_id);
        if (!token_key.has_value())
        {
          error_reason = "JWT signing key not found";
        }
        else if (!http::JwtVerifier::validate_token_signature(
                   token.value(), token_key.value()))
        {
          error_reason = "JWT signature is invalid";
        }
        else
        {
          auto identity = std::make_unique<JwtAuthnIdentity>();
          identity->key_issuer = key_issuer_view->get(key_id).value();
          identity->header = token->header;
          identity->payload = token->payload;
          return identity;
        }
      }

      // TODO: maintain error_reason
      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx,
      std::string&& error_reason) override
    {
      ctx->set_response_status(HTTP_STATUS_UNAUTHORIZED);
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        "Bearer realm=\"JWT bearer token access\", error=\"invalid_token\"");
      ctx->set_response_body(std::move(error_reason));
    }

    const OpenAPISecuritySchema& get_openapi_security_schema() const override
    {
      return security_schema;
    }
  };

  inline const AuthnPolicy::OpenAPISecuritySchema JwtAuthnPolicy::security_schema =
    std::make_pair(
      "bearer_jwt",
      nlohmann::json{
        {"type", "http"}, {"scheme", "bearer"}, {"bearerFormat", "JWT"}});
}
