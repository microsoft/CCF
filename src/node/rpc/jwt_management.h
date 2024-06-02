// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/proposals.h"
#include "ccf/tx.h"
#include "http/http_jwt.h"

#ifdef SGX_ATTESTATION_VERIFICATION
#  include <openenclave/attestation/verifier.h>
#endif

#include <set>
#include <sstream>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#elif defined(SGX_ATTESTATION_VERIFICATION)
#  include <openenclave/host_verify.h>
#endif

namespace ccf
{
  static void legacy_remove_jwt_public_signing_keys(
    kv::Tx& tx, std::string issuer)
  {
    auto keys =
      tx.rw<JwtPublicSigningKeys>(Tables::Legacy::JWT_PUBLIC_SIGNING_KEYS);
    auto key_issuer = tx.rw<Tables::Legacy::JwtPublicSigningKeyIssuer>(
      Tables::Legacy::JWT_PUBLIC_SIGNING_KEY_ISSUER);

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

  static bool check_issuer(
    const std::string& issuer, const std::string& constraint)
  {
    const auto issuer_domain = http::parse_url_full(issuer).host;
    const auto constraint_domain = http::parse_url_full(constraint).host;

    if (constraint_domain.empty())
    {
      return false;
    }

    // Either constraint's domain == issuer's domain or it is a subdomain, e.g.:
    // limited.facebook.com
    //        .facebook.com
    if (issuer_domain != constraint_domain)
    {
      const auto pattern = "." + constraint_domain;
      return issuer_domain.ends_with(pattern);
    }

    return true;
  }

  static void remove_jwt_public_signing_keys(kv::Tx& tx, std::string issuer)
  {
    // Unlike resetting JWT keys for a particular issuer, removing keys can be
    // safely done on both table revisions, as soon as the application shouldn't
    // use them anyway after being ask about that explicitly.
    legacy_remove_jwt_public_signing_keys(tx, issuer);

    auto keys =
      tx.rw<JwtPublicSigningKeys>(Tables::JWT_PUBLIC_SIGNING_KEY_CERTS);
    auto key_issuers =
      tx.rw<JwtPublicSigningKeyIssuers>(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUERS);

    key_issuers->foreach(
      [&issuer, &keys, &key_issuers](const auto& k, const auto& v) {
        auto it =
          find_if(v.begin(), v.end(), [&](const auto& issuer_with_constraint) {
            return issuer_with_constraint.issuer == issuer;
          });

        if (it != v.end())
        {
          std::vector<JwtIssuerWithConstraint> updated(v.begin(), it);
          updated.insert(updated.end(), ++it, v.end());

          if (!updated.empty())
          {
            key_issuers->put(k, updated);
          }
          else
          {
            keys->remove(k);
            key_issuers->remove(k);
          }
        }
        return true;
      });
  }

#ifdef SGX_ATTESTATION_VERIFICATION
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
#endif

  static bool set_jwt_public_signing_keys(
    kv::Tx& tx,
    const ProposalId& proposal_id,
    std::string issuer,
    const JwtIssuerMetadata& issuer_metadata,
    const JsonWebKeySet& jwks)
  {
    auto keys =
      tx.rw<JwtPublicSigningKeys>(Tables::JWT_PUBLIC_SIGNING_KEY_CERTS);
    auto key_issuers =
      tx.rw<JwtPublicSigningKeyIssuers>(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUERS);

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
    std::map<std::string, JwtIssuer> issuer_constraints;
    for (auto& jwk : jwks.keys)
    {
      if (!jwk.kid.has_value())
      {
        LOG_FAIL_FMT("No kid for JWT signing key");
        return false;
      }

      if (!jwk.x5c.has_value() && jwk.x5c->empty())
      {
        LOG_FAIL_FMT("{}: JWKS is invalid (empty x5c)", log_prefix);
        return false;
      }

      auto& der_base64 = jwk.x5c.value()[0];
      ccf::Cert der;
      auto const& kid = jwk.kid.value();
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

      if (keys->has(kid) && der != keys->get(kid))
      {
        LOG_FAIL_FMT(
          "{}: key id {} has been added before with a different pem",
          log_prefix,
          kid,
          issuer);
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
#ifdef SGX_ATTESTATION_VERIFICATION
        oe_verify_attestation_certificate_with_evidence(
          der.data(),
          der.size(),
          oe_verify_attestation_certificate_with_evidence_cb,
          &claims);
#else
        LOG_FAIL_FMT("{}: SGX claims not supported", log_prefix);
        return false;
#endif
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

      if (jwk.issuer)
      {
        if (!check_issuer(issuer, *jwk.issuer))
        {
          LOG_FAIL_FMT(
            "{}: JWKS kid {} with issuer constraint {} fails validation "
            "against issuer {}",
            log_prefix,
            kid,
            *jwk.issuer,
            issuer);
          return false;
        }

        issuer_constraints.emplace(kid, *jwk.issuer);
      }
    }

    if (new_keys.empty())
    {
      LOG_FAIL_FMT("{}: no keys left after applying filter", log_prefix);
      return false;
    }

    std::set<std::string> existing_kids;
    std::set<std::string> kids_with_new_constraints;
    key_issuers->foreach([&existing_kids,
                          &issuer_constraints,
                          &kids_with_new_constraints,
                          &issuer](const auto& kid, const auto& issuers) {
      for (const auto& issuer_with_constraint : issuers)
      {
        if (issuer == issuer_with_constraint.issuer)
        {
          existing_kids.insert(kid);

          const auto it = issuer_constraints.find(kid);
          if (
            it != issuer_constraints.end() &&
            it->second == issuer_with_constraint.constraint)
          {
            kids_with_new_constraints.insert(kid);
          }

          break; // 1 issuer <-> 1 kid
        }
      }
      return true;
    });

    for (auto& [kid, der] : new_keys)
    {
      const bool new_kid = !existing_kids.contains(kid);
      const bool new_constraint = !kids_with_new_constraints.contains(kid);

      if (new_kid)
      {
        keys->put(kid, der);
      }

      if (new_kid || new_constraint)
      {
        JwtIssuerWithConstraint value{issuer, std::nullopt};
        const auto it = issuer_constraints.find(kid);
        if (it != issuer_constraints.end())
        {
          value.constraint = it->second;
        }

        LOG_DEBUG_FMT(
          "Save JWT issuer for kid {} where issuer: {}, issuer constraint: {}",
          kid,
          value.issuer,
          value.constraint);

        auto existing_issuers = key_issuers->get(kid);
        if (existing_issuers)
        {
          const auto prev = find_if(
            existing_issuers->begin(),
            existing_issuers->end(),
            [&](const auto& issuer_with_constraint) {
              return issuer_with_constraint.issuer == issuer;
            });

          if (prev != existing_issuers->end())
          {
            *prev = value;
          }
          else
          {
            existing_issuers->push_back(std::move(value));
          }
          key_issuers->put(kid, *existing_issuers);
        }
        else
        {
          key_issuers->put(kid, std::vector<JwtIssuerWithConstraint>{value});
        }
      }
    }

    for (auto& kid : existing_kids)
    {
      if (!new_keys.contains(kid))
      {
        auto updated = key_issuers->get(kid);
        updated->erase(
          std::remove_if(
            updated->begin(),
            updated->end(),
            [&](const auto& issuer_with_constraint) {
              return issuer_with_constraint.issuer == issuer;
            }),
          updated->end());

        if (updated->empty())
        {
          keys->remove(kid);
          key_issuers->remove(kid);
        }
        else
        {
          key_issuers->put(kid, *updated);
        }
      }
    }

    return true;
  }
}