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

}

namespace ccf
{
  bool validate_issuer(
    const std::string& iss,
    const std::optional<std::string>& tid,
    std::string constraint)
  {
    LOG_DEBUG_FMT(
      "Verify token.iss {} and token.tid {} against published key issuer {}",
      iss,
      tid,
      constraint);

    const auto issuer_url = ::http::parse_url_full(constraint);
    if (issuer_url.host != microsoft_entra_domain)
    {
      return iss == constraint &&
        !tid; // tid is a MSFT-specific claim and
              // shoudn't be set for a non-Entra issuer.
    }

    // Specify tenant if working with multi-tenant endpoint.
    const auto pos = constraint.find(multitenancy_indicator);
    if (pos != std::string::npos && tid)
    {
      constraint.replace(pos, multitenancy_indicator.size(), *tid);
    }

    // Step 1. Verify the token issuer against the key issuer.
    if (iss != constraint)
    {
      return false;
    }

    // Step 2. Verify that token.tid is served as a part of token.iss. According
    // to the documentation, we only accept this format:
    //
    // https://domain.com/tenant_id/something_else
    //
    // Here url.path == "/tenant_id/something_else".
    //
    // Check for details here:
    // https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-the-issuer.

    const auto url = ::http::parse_url_full(iss);
    const auto tenant_id =
      first_non_empty_chunk(ccf::nonstd::split(url.path, "/"));

    return tenant_id && tid && *tid == *tenant_id;
  }

  struct VerifiersCache
  {
    static constexpr size_t DEFAULT_MAX_VERIFIERS = 10;

    using DER = std::vector<uint8_t>;
    ccf::pal::Mutex verifiers_lock;
    LRU<DER, ccf::crypto::VerifierPtr> verifiers;

    VerifiersCache(size_t max_verifiers = DEFAULT_MAX_VERIFIERS) :
      verifiers(max_verifiers)
    {}

    ccf::crypto::VerifierPtr get_verifier(const DER& der)
    {
      std::lock_guard<ccf::pal::Mutex> guard(verifiers_lock);

      auto it = verifiers.find(der);
      if (it == verifiers.end())
      {
        it = verifiers.insert(der, ccf::crypto::make_unique_verifier(der));
      }

      return it->second;
    }
  };

  JwtAuthnPolicy::JwtAuthnPolicy() :
    verifiers(std::make_unique<VerifiersCache>())
  {}

  JwtAuthnPolicy::~JwtAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> JwtAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& headers = ctx->get_request_headers();
    error_reason = "Invalid JWT token";

    const auto token_opt =
      ::http::JwtVerifier::extract_token(headers, error_reason);
    if (!token_opt)
    {
      return nullptr;
    }

    auto& token = token_opt.value();
    auto keys = tx.ro<JwtPublicSigningKeys>(
      ccf::Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);
    const auto key_id = token.header_typed.kid;
    auto token_keys = keys->get(key_id);

    if (!token_keys)
    {
      auto fallback_keys = tx.ro<Tables::Legacy::JwtPublicSigningKeys>(
        ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEYS);
      auto fallback_issuers = tx.ro<Tables::Legacy::JwtPublicSigningKeyIssuer>(
        ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEY_ISSUER);

      auto fallback_key = fallback_keys->get(key_id);
      if (fallback_key)
      {
        token_keys = std::vector<OpenIDJWKMetadata>{OpenIDJWKMetadata{
          .cert = *fallback_key,
          .issuer = *fallback_issuers->get(key_id),
          .constraint = std::nullopt}};
      }
    }

    if (!token_keys || token_keys->empty())
    {
      error_reason =
        fmt::format("JWT signing key not found for kid {}", key_id);
      return nullptr;
    }

    for (const auto& metadata : *token_keys)
    {
      auto verifier = verifiers->get_verifier(metadata.cert);
      if (!::http::JwtVerifier::validate_token_signature(token, verifier))
      {
        error_reason =
          "Signature verification failed";
        continue;
      }

      // Check that the Not Before and Expiration Time claims are valid
      const size_t time_now = std::chrono::duration_cast<std::chrono::seconds>(
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
        metadata.constraint &&
        !validate_issuer(
          token.payload_typed.iss,
          token.payload_typed.tid,
          *metadata.constraint))
      {
        error_reason = fmt::format(
          "Kid {} failed issuer constraint validation {}",
          key_id,
          *metadata.constraint);
      }
      else
      {
        auto identity = std::make_unique<JwtAuthnIdentity>();
        identity->key_issuer = metadata.issuer;
        identity->header = std::move(token.header);
        identity->payload = std::move(token.payload);
        return identity;
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
