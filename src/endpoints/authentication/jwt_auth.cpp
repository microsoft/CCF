// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/jwt_auth.h"

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/public_key.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/ds/nonstd.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/jwt.h"
#include "ds/lru.h"
#include "enclave/enclave_time.h"
#include "http/http_jwt.h"

namespace
{
  const std::string multitenancy_indicator{"{tenantid}"};
  const std::string microsoft_entra_domain{"login.microsoftonline.com"};

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

  struct PublicKeysCache
  {
    static constexpr size_t DEFAULT_MAX_KEYS = 10;

    using DER = std::vector<uint8_t>;
    using KeyVariant =
      std::variant<ccf::crypto::RSAPublicKeyPtr, ccf::crypto::PublicKeyPtr>;
    ccf::pal::Mutex keys_lock;
    LRU<DER, KeyVariant> keys;

    PublicKeysCache(size_t max_keys = DEFAULT_MAX_KEYS) : keys(max_keys) {}

    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      const DER& der)
    {
      std::lock_guard<ccf::pal::Mutex> guard(keys_lock);

      auto it = keys.find(der);
      if (it == keys.end())
      {
        try
        {
          it = keys.insert(der, ccf::crypto::make_rsa_public_key(der));
        }
        catch (const std::exception&)
        {
          it = keys.insert(der, ccf::crypto::make_public_key(der));
        }
      }

      const auto& key = it->second;
      if (std::holds_alternative<ccf::crypto::RSAPublicKeyPtr>(key))
      {
        LOG_DEBUG_FMT("Verify der: {} as RSA key", der);

        // Obsolete PKCS1 padding is chosen for JWT, as explained in details in
        // https://github.com/microsoft/CCF/issues/6601#issuecomment-2512059875.
        return std::get<ccf::crypto::RSAPublicKeyPtr>(key)->verify_pkcs1(
          contents,
          contents_size,
          signature,
          signature_size,
          ccf::crypto::MDType::SHA256);
      }
      
      if (std::holds_alternative<ccf::crypto::PublicKeyPtr>(key))
      {
        LOG_DEBUG_FMT("Verify der: {} as EC key", der);

        const auto sig_der =
          ccf::crypto::ecdsa_sig_p1363_to_der({signature, signature_size});
        return std::get<ccf::crypto::PublicKeyPtr>(key)->verify(
          contents,
          contents_size,
          sig_der.data(),
          sig_der.size(),
          ccf::crypto::MDType::SHA256);
      }

      LOG_DEBUG_FMT("Key not found for der: {}", der);
      return false;
    }
  };

  JwtAuthnPolicy::JwtAuthnPolicy() :
    keys_cache(std::make_unique<PublicKeysCache>())
  {}

  JwtAuthnPolicy::~JwtAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> JwtAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& headers = ctx->get_request_headers();

    const auto token_opt =
      ::http::JwtVerifier::extract_token(headers, error_reason);
    if (!token_opt)
    {
      return nullptr;
    }

    const auto& token = token_opt.value();
    auto * keys = tx.ro<JwtPublicSigningKeysMetadata>(
      ccf::Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);
    const auto key_id = token.header_typed.kid;
    auto token_keys = keys->get(key_id);

    // For metadata KID->(cert,issuer,constraint).
    //
    // Note, that Legacy keys are stored as certs, new approach is raw keys, so
    // conversion from cert to raw key is needed.
    if (!token_keys)
    {
      auto * fallback_certs = tx.ro<JwtPublicSigningKeysMetadataLegacy>(
        ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEYS_METADATA);
      auto fallback_data = fallback_certs->get(key_id);
      if (fallback_data)
      {
        auto new_keys = std::vector<OpenIDJWKMetadata>();
        for (const auto& metadata : *fallback_data)
        {
          auto verifier = ccf::crypto::make_unique_verifier(metadata.cert);
          new_keys.push_back(OpenIDJWKMetadata{
            .public_key = verifier->public_key_der(),
            .issuer = metadata.issuer,
            .constraint = metadata.constraint});
        }
        if (!new_keys.empty())
        {
          token_keys = new_keys;
        }
      }
    }

    // For metadata as two separate tables, KID->JwtIssuer and KID->Cert.
    //
    // Note, that Legacy keys are stored as certs, new approach is raw keys, so
    // conversion from certs to keys is needed.
    if (!token_keys)
    {
      auto * fallback_keys = tx.ro<Tables::Legacy::JwtPublicSigningKeys>(
        ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEYS);
      auto * fallback_issuers = tx.ro<Tables::Legacy::JwtPublicSigningKeyIssuer>(
        ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEY_ISSUER);

      auto fallback_cert = fallback_keys->get(key_id);
      auto fallback_issuer = fallback_issuers->get(key_id);
      if (fallback_cert)
      {
        if (!fallback_issuer)
        {
          error_reason =
            fmt::format("JWT signing key fallback issuers not found for kid {}", key_id);
          return nullptr;
        }
        auto verifier = ccf::crypto::make_unique_verifier(*fallback_cert);
        token_keys = std::vector<OpenIDJWKMetadata>{OpenIDJWKMetadata{
          .public_key = verifier->public_key_der(),
          .issuer = fallback_issuer.value(),
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
      if (!keys_cache->verify(
            reinterpret_cast<const uint8_t*>(token.signed_content.data()),
            token.signed_content.size(),
            token.signature.data(),
            token.signature.size(),
            metadata.public_key))
      {
        error_reason = "Signature verification failed";
        continue;
      }

      // Check that the Not Before and Expiration Time claims are valid
      const size_t time_now = std::chrono::duration_cast<std::chrono::seconds>(
                                ccf::get_enclave_time())
                                .count();
      if (token.payload_typed.nbf && time_now < *token.payload_typed.nbf)
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
        identity->header = token.header;
        identity->payload = token.payload;
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
      R"(Bearer realm="JWT bearer token access", error="invalid_token")");
  }

  const OpenAPISecuritySchema JwtAuthnPolicy::security_schema = std::make_pair(
    JwtAuthnPolicy::SECURITY_SCHEME_NAME,
    nlohmann::json{
      {"type", "http"}, {"scheme", "bearer"}, {"bearerFormat", "JWT"}});
}
