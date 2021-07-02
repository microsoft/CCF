// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/verifier.h"
#include "ds/json.h"
#include "entities.h"
#include "proposals.h"
#include "service_map.h"

#include <openenclave/attestation/verifier.h>
#include <optional>
#include <set>
#include <sstream>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif

namespace ccf
{
  struct JwtIssuerKeyPolicy
  {
    /** OE claim name -> hex-encoded claim value
        See openenclave/attestation/verifier.h */
    std::optional<std::map<std::string, std::string>> sgx_claims;

    bool operator!=(const JwtIssuerKeyPolicy& rhs) const
    {
      return rhs.sgx_claims != sgx_claims;
    }
  };

  DECLARE_JSON_TYPE(JwtIssuerKeyPolicy);
  DECLARE_JSON_REQUIRED_FIELDS(JwtIssuerKeyPolicy, sgx_claims);

  enum class JwtIssuerKeyFilter
  {
    All,
    SGX
  };

  DECLARE_JSON_ENUM(
    JwtIssuerKeyFilter,
    {{JwtIssuerKeyFilter::All, "all"}, {JwtIssuerKeyFilter::SGX, "sgx"}});

  struct JwtIssuerMetadata
  {
    /// JWT issuer key filter
    JwtIssuerKeyFilter key_filter;
    /// Optional Key Policy
    std::optional<JwtIssuerKeyPolicy> key_policy;
    /// Optional CA bundle name used for authentication when auto-refreshing
    std::optional<std::string> ca_cert_bundle_name;
    /// Whether to auto-refresh keys from the issuer
    bool auto_refresh = false;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JwtIssuerMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(JwtIssuerMetadata, key_filter);
  DECLARE_JSON_OPTIONAL_FIELDS(
    JwtIssuerMetadata, key_policy, ca_cert_bundle_name, auto_refresh);

  using JwtIssuer = std::string;
  using JwtKeyId = std::string;

  using JwtIssuers = ServiceMap<JwtIssuer, JwtIssuerMetadata>;
  using JwtPublicSigningKeys = kv::RawCopySerialisedMap<JwtKeyId, Cert>;
  using JwtPublicSigningKeyIssuer =
    kv::RawCopySerialisedMap<JwtKeyId, JwtIssuer>;

  struct JsonWebKey
  {
    std::vector<std::string> x5c;
    std::string kid;
    std::string kty;

    bool operator==(const JsonWebKey& rhs) const
    {
      return x5c == rhs.x5c && kid == rhs.kid && kty == rhs.kty;
    }
  };
  DECLARE_JSON_TYPE(JsonWebKey)
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKey, x5c, kid, kty)

  struct JsonWebKeySet
  {
    std::vector<JsonWebKey> keys;

    bool operator!=(const JsonWebKeySet& rhs) const
    {
      return keys != rhs.keys;
    }
  };
  DECLARE_JSON_TYPE(JsonWebKeySet)
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeySet, keys)

// Unused in all sample apps, but used by node frontend
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
  static void remove_jwt_public_signing_keys(kv::Tx& tx, std::string issuer)
  {
    auto keys = tx.rw<JwtPublicSigningKeys>(Tables::JWT_PUBLIC_SIGNING_KEYS);
    auto key_issuer =
      tx.rw<JwtPublicSigningKeyIssuer>(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER);

    key_issuer->foreach(
      [&issuer, &keys, &key_issuer](const auto& k, const auto& v) {
        if (v == issuer)
        {
          keys->remove(k);
          key_issuer->remove(k);
        }
        return true;
      });
  }

  static oe_result_t oe_verify_attestation_certificate_with_evidence_cb(
    oe_claim_t* claims, size_t claims_length, void* arg)
  {
    auto claims_map = (std::map<std::string, std::vector<uint8_t>>*)arg;
    for (size_t i = 0; i < claims_length; i++)
    {
      std::string claim_name(claims[i].name);
      std::vector<uint8_t> claim_value(
        claims[i].value, claims[i].value + claims[i].value_size);
      claims_map->emplace(std::move(claim_name), std::move(claim_value));
    }
    return OE_OK;
  }

  static bool set_jwt_public_signing_keys(
    kv::Tx& tx,
    const ProposalId& proposal_id,
    std::string issuer,
    const JwtIssuerMetadata& issuer_metadata,
    const JsonWebKeySet& jwks)
  {
    auto keys = tx.rw<JwtPublicSigningKeys>(Tables::JWT_PUBLIC_SIGNING_KEYS);
    auto key_issuer =
      tx.rw<JwtPublicSigningKeyIssuer>(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER);

    auto log_prefix = proposal_id.empty() ?
      "JWT key auto-refresh" :
      fmt::format("Proposal {}", proposal_id);

    // add keys
    if (jwks.keys.empty())
    {
      LOG_FAIL_FMT("{}: JWKS has no keys", log_prefix, proposal_id);
      return false;
    }
    std::map<std::string, std::vector<uint8_t>> new_keys;
    for (auto& jwk : jwks.keys)
    {
      if (keys->has(jwk.kid) && key_issuer->get(jwk.kid).value() != issuer)
      {
        LOG_FAIL_FMT(
          "{}: key id {} already added for different issuer",
          log_prefix,
          jwk.kid);
        return false;
      }
      if (jwk.x5c.empty())
      {
        LOG_FAIL_FMT("{}: JWKS is invalid (empty x5c)", log_prefix);
        return false;
      }

      auto& der_base64 = jwk.x5c[0];
      ccf::Cert der;
      try
      {
        der = tls::raw_from_b64(der_base64);
      }
      catch (const std::invalid_argument& e)
      {
        LOG_FAIL_FMT(
          "{}: Could not parse x5c of key id {}: {}",
          log_prefix,
          jwk.kid,
          e.what());
        return false;
      }

      std::map<std::string, std::vector<uint8_t>> claims;
      bool has_key_policy_sgx_claims = issuer_metadata.key_policy.has_value() &&
        issuer_metadata.key_policy.value().sgx_claims.has_value() &&
        !issuer_metadata.key_policy.value().sgx_claims.value().empty();
      if (
        issuer_metadata.key_filter == JwtIssuerKeyFilter::SGX ||
        has_key_policy_sgx_claims)
      {
        oe_verify_attestation_certificate_with_evidence(
          der.data(),
          der.size(),
          oe_verify_attestation_certificate_with_evidence_cb,
          &claims);
      }

      if (
        issuer_metadata.key_filter == JwtIssuerKeyFilter::SGX && claims.empty())
      {
        LOG_INFO_FMT(
          "{}: Skipping JWT signing key with kid {} (not OE "
          "attested)",
          log_prefix,
          jwk.kid);
        continue;
      }

      if (has_key_policy_sgx_claims)
      {
        for (auto& [claim_name, expected_claim_val_hex] :
             issuer_metadata.key_policy.value().sgx_claims.value())
        {
          if (claims.find(claim_name) == claims.end())
          {
            LOG_FAIL_FMT(
              "{}: JWKS kid {} is missing the {} SGX claim",
              log_prefix,
              jwk.kid,
              claim_name);
            return false;
          }
          auto& actual_claim_val = claims[claim_name];
          auto actual_claim_val_hex = ds::to_hex(actual_claim_val);
          if (expected_claim_val_hex != actual_claim_val_hex)
          {
            LOG_FAIL_FMT(
              "{}: JWKS kid {} has a mismatching {} SGX claim: {} != {}",
              log_prefix,
              jwk.kid,
              claim_name,
              expected_claim_val_hex,
              actual_claim_val_hex);
            return false;
          }
        }
      }
      else
      {
        try
        {
          crypto::check_is_cert(der);
        }
        catch (std::invalid_argument& exc)
        {
          LOG_FAIL_FMT(
            "{}: JWKS kid {} has an invalid X.509 certificate: {}",
            log_prefix,
            jwk.kid,
            exc.what());
          return false;
        }
      }
      LOG_INFO_FMT(
        "{}: Storing JWT signing key with kid {}", log_prefix, jwk.kid);
      new_keys.emplace(jwk.kid, der);
    }
    if (new_keys.empty())
    {
      LOG_FAIL_FMT("{}: no keys left after applying filter", log_prefix);
      return false;
    }

    remove_jwt_public_signing_keys(tx, issuer);
    for (auto& [kid, der] : new_keys)
    {
      keys->put(kid, der);
      key_issuer->put(kid, issuer);
    }

    return true;
  }
#pragma clang diagnostic pop
}