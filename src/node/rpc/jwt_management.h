// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/service/tables/jwt.h"

#include <openenclave/attestation/verifier.h>
#include <set>
#include <sstream>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif

namespace ccf
{
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
      if (!jwk.kid.has_value())
      {
        LOG_FAIL_FMT("No kid for JWT signing key");
        return false;
      }
      auto const& kid = jwk.kid.value();

      if (keys->has(kid) && key_issuer->get(kid).value() != issuer)
      {
        LOG_FAIL_FMT(
          "{}: key id {} already added for different issuer", log_prefix, kid);
        return false;
      }
      if (!jwk.x5c.has_value() && jwk.x5c->empty())
      {
        LOG_FAIL_FMT("{}: JWKS is invalid (empty x5c)", log_prefix);
        return false;
      }

      auto& der_base64 = jwk.x5c.value()[0];
      ccf::Cert der;
      try
      {
        der = crypto::raw_from_b64(der_base64);
      }
      catch (const std::invalid_argument& e)
      {
        LOG_FAIL_FMT(
          "{}: Could not parse x5c of key id {}: {}",
          log_prefix,
          kid,
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
          kid);
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
              kid,
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
              kid,
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
          crypto::make_unique_verifier(
            (std::vector<uint8_t>)der); // throws on error
        }
        catch (std::invalid_argument& exc)
        {
          LOG_FAIL_FMT(
            "{}: JWKS kid {} has an invalid X.509 certificate: {}",
            log_prefix,
            kid,
            exc.what());
          return false;
        }
      }
      LOG_INFO_FMT("{}: Storing JWT signing key with kid {}", log_prefix, kid);
      new_keys.emplace(kid, der);
    }
    if (new_keys.empty())
    {
      LOG_FAIL_FMT("{}: no keys left after applying filter", log_prefix);
      return false;
    }

    std::set<std::string> existing_kids;
    key_issuer->foreach(
      [&existing_kids, &issuer](const auto& kid, const auto& issuer_) {
        if (issuer_ == issuer)
        {
          existing_kids.insert(kid);
        }
        return true;
      });

    for (auto& [kid, der] : new_keys)
    {
      if (!existing_kids.contains(kid))
      {
        keys->put(kid, der);
        key_issuer->put(kid, issuer);
      }
    }

    for (auto& kid : existing_kids)
    {
      if (!new_keys.contains(kid))
      {
        keys->remove(kid);
        key_issuer->remove(kid);
      }
    }

    return true;
  }
}