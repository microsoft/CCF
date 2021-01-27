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
    /** JWT key issuer, as defined in @c
     * public:ccf.gov.jwt_public_signing_key_issuer */
    std::string key_issuer;
    /** JWT header */
    nlohmann::json header;
    /** JWT payload */
    nlohmann::json payload;
  };

  class JwtAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "jwt";

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
        auto keys =
          tx.ro<JwtPublicSigningKeys>(ccf::Tables::JWT_PUBLIC_SIGNING_KEYS);
        auto key_issuers = tx.ro<JwtPublicSigningKeyIssuer>(
          ccf::Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER);
        const auto key_id = token.value().header_typed.kid;
        const auto token_key = keys->get(key_id);
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
          identity->key_issuer = key_issuers->get(key_id).value();
          identity->header = std::move(token->header);
          identity->payload = std::move(token->payload);
          return identity;
        }
      }

      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx,
      std::string&& error_reason) override
    {
      ctx->set_error(
        HTTP_STATUS_UNAUTHORIZED,
        ccf::errors::InvalidAuthenticationInfo,
        std::move(error_reason));
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        "Bearer realm=\"JWT bearer token access\", error=\"invalid_token\"");
    }

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return security_schema;
    }
  };

  inline const OpenAPISecuritySchema JwtAuthnPolicy::security_schema =
    std::make_pair(
      JwtAuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"}, {"scheme", "bearer"}, {"bearerFormat", "JWT"}});
}
