// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/jwt_auth.h"

#include "ccf/ds/nonstd.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/jwt.h"
#include "ds/lru.h"
#include "enclave/enclave_time.h"
#include "http/http_jwt.h"

namespace
{
  static const std::string multitenancy_indicator{"{tenantid}"};
  static const std::string microsoft_entra_domain{"login.microsoftonline.com"};

  std::optional<std::string_view> first_non_empty_chunk(
    const std::vector<std::string_view>& chunks)
  {
    for (auto chunk : chunks)
    {
      if (!chunk.empty())
      {
        return chunk;
      }
    }
    return std::nullopt;
  }

  bool validate_issuer(
    const http::JwtVerifier::Token& token, std::string issuer)
  {
    LOG_DEBUG_FMT(
      "Verify token.iss {} and token.tid {} against published key issuer {}",
      token.payload_typed.iss,
      token.payload_typed.tid,
      issuer);

    const bool is_microsoft_entra =
      issuer.find(microsoft_entra_domain) != std::string::npos;
    if (!is_microsoft_entra)
    {
      return token.payload_typed.iss == issuer;
    }

    // Specify tenant if working with multi-tenant endpoint.
    const auto pos = issuer.find(multitenancy_indicator);
    if (pos != std::string::npos && token.payload_typed.tid)
    {
      issuer.replace(
        pos, multitenancy_indicator.size(), *token.payload_typed.tid);
    }

    // Step 1. Verify the token issuer against the key issuer.
    if (token.payload_typed.iss != issuer)
    {
      return false;
    }

    // Step 2. Verify that token.tid is served as a part of token.iss. According
    // to the documentation, we only accept this format:
    //
    // https://domain.com/tenant_id/something_else
    //
    // Here url.path == "/tenant_id/something_else".

    const auto url = http::parse_url_full(token.payload_typed.iss);
    const auto tenant_id = first_non_empty_chunk(nonstd::split(url.path, "/"));

    return (
      tenant_id && token.payload_typed.tid &&
      *token.payload_typed.tid == *tenant_id);
  }

  bool validate_issuers(
    const http::JwtVerifier::Token& token,
    const std::vector<ccf::JwtIssuerWithConstraint>& issuers,
    std::string& validated_issuer)
  {
    return std::any_of(issuers.begin(), issuers.end(), [&](const auto& issuer) {
      if (issuer.constraint && validate_issuer(token, *issuer.constraint))
      {
        validated_issuer = issuer.issuer;
        return true;
      }
      return false;
    });
  }

}

namespace ccf
{
  struct VerifiersCache
  {
    static constexpr size_t DEFAULT_MAX_VERIFIERS = 10;

    using DER = std::vector<uint8_t>;
    ccf::pal::Mutex verifiers_lock;
    LRU<DER, crypto::VerifierPtr> verifiers;

    VerifiersCache(size_t max_verifiers = DEFAULT_MAX_VERIFIERS) :
      verifiers(max_verifiers)
    {}

    crypto::VerifierPtr get_verifier(const DER& der)
    {
      std::lock_guard<ccf::pal::Mutex> guard(verifiers_lock);

      auto it = verifiers.find(der);
      if (it == verifiers.end())
      {
        it = verifiers.insert(der, crypto::make_unique_verifier(der));
      }

      return it->second;
    }
  };

  JwtAuthnPolicy::JwtAuthnPolicy() :
    verifiers(std::make_unique<VerifiersCache>())
  {}

  JwtAuthnPolicy::~JwtAuthnPolicy() = default;

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
        tx.ro<JwtPublicSigningKeys>(ccf::Tables::JWT_PUBLIC_SIGNING_KEY_CERTS);
      auto key_issuers = tx.ro<JwtPublicSigningKeyIssuers>(
        ccf::Tables::JWT_PUBLIC_SIGNING_KEY_ISSUERS);
      const auto key_id = token.header_typed.kid;
      auto token_key = keys->get(key_id);
      const auto issuers = key_issuers->get(key_id);
      std::string validated_issuer{};

      if (!token_key.has_value())
      {
        auto fallback_keys = tx.ro<JwtPublicSigningKeys>(
          ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEYS);
        token_key = fallback_keys->get(key_id);
      }

      if (!token_key.has_value())
      {
        error_reason = "JWT signing key not found";
      }
      else
      {
        auto verifier = verifiers->get_verifier(token_key.value());
        if (!http::JwtVerifier::validate_token_signature(token, verifier))
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
          else if (
            issuers &&
            !validate_issuers(token, *issuers, std::ref(validated_issuer)))
          {
            error_reason =
              fmt::format("Kid {} failed issuer validation", key_id);
          }
          else
          {
            auto identity = std::make_unique<JwtAuthnIdentity>();

            if (validated_issuer.empty())
            {
              auto fallback_issuers =
                tx.ro<ccf::Tables::Legacy::JwtPublicSigningKeyIssuer>(
                  ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEY_ISSUER);
              const auto& issuer = fallback_issuers->get(key_id);
              if (issuer)
              {
                validated_issuer = *issuer;
              }
            }

            identity->key_issuer = validated_issuer;
            identity->header = std::move(token.header);
            identity->payload = std::move(token.payload);
            return identity;
          }
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
