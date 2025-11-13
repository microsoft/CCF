// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/proposals.h"
#include "ccf/tx.h"
#include "http/http_jwt.h"

#include <set>
#include <sstream>

namespace
{
  std::vector<uint8_t> try_parse_raw_rsa(const ccf::crypto::JsonWebKeyData& jwk)
  {
    if (!jwk.e || jwk.e->empty() || !jwk.n || jwk.n->empty())
    {
      return {};
    }

    std::vector<uint8_t> der;
    ccf::crypto::JsonWebKeyRSAPublic data;
    data.kty = ccf::crypto::JsonWebKeyType::RSA;
    data.kid = jwk.kid.value();
    data.n = jwk.n.value();
    data.e = jwk.e.value();
    try
    {
      const auto pubkey = ccf::crypto::make_rsa_public_key(data);
      return pubkey->public_key_der();
    }
    catch (const std::invalid_argument& exc)
    {
      throw std::logic_error(
        fmt::format("Failed to construct RSA public key: {}", exc.what()));
    }
  }

  std::vector<uint8_t> try_parse_raw_ec(const ccf::crypto::JsonWebKeyData& jwk)
  {
    if (!jwk.x || jwk.x->empty() || !jwk.y || jwk.y->empty() || !jwk.crv)
    {
      return {};
    }

    ccf::crypto::JsonWebKeyECPublic data;
    data.kty = ccf::crypto::JsonWebKeyType::EC;
    data.kid = jwk.kid.value();
    data.crv = jwk.crv.value();
    data.x = jwk.x.value();
    data.y = jwk.y.value();
    try
    {
      const auto pubkey = ccf::crypto::make_public_key(data);
      return pubkey->public_key_der();
    }
    catch (const std::invalid_argument& exc)
    {
      throw std::logic_error(
        fmt::format("Failed to construct EC public key: {}", exc.what()));
    }
  }

  std::vector<uint8_t> try_parse_x5c(const ccf::crypto::JsonWebKeyData& jwk)
  {
    if (!jwk.x5c || jwk.x5c->empty())
    {
      return {};
    }

    const auto& kid = jwk.kid.value();
    auto& der_base64 = jwk.x5c.value()[0];
    ccf::Cert der;
    try
    {
      der = ccf::crypto::raw_from_b64(der_base64);
    }
    catch (const std::invalid_argument& e)
    {
      throw std::logic_error(
        fmt::format("Could not parse x5c of key id {}: {}", kid, e.what()));
    }
    try
    {
      auto verifier = ccf::crypto::make_unique_verifier(der);
      return verifier->public_key_der();
    }
    catch (std::invalid_argument& exc)
    {
      throw std::logic_error(fmt::format(
        "JWKS kid {} has an invalid X.509 certificate: {}", kid, exc.what()));
    }
  }

  std::vector<uint8_t> try_parse_jwk(const ccf::crypto::JsonWebKeyData& jwk)
  {
    const auto& kid = jwk.kid.value();
    auto key = try_parse_raw_rsa(jwk);
    if (!key.empty())
    {
      return key;
    }
    key = try_parse_raw_ec(jwk);
    if (!key.empty())
    {
      return key;
    }
    key = try_parse_x5c(jwk);
    if (!key.empty())
    {
      return key;
    }

    throw std::logic_error(
      fmt::format("JWKS kid {} has neither RSA/EC public key or x5c", kid));
  }
}

namespace ccf
{
  static bool check_issuer_constraint(
    const std::string& issuer, const std::string& constraint)
  {
    // Only accept key constraints for the same (sub)domain. This is to avoid
    // setting keys from issuer A which will be used to validate iss claims
    // for issuer B, so this doesn't make sense (at least for now).

    const auto issuer_domain = ::http::parse_url_full(issuer).host;
    const auto constraint_domain = ::http::parse_url_full(constraint).host;

    if (constraint_domain.empty())
    {
      return false;
    }

    // Either constraint's domain == issuer's domain or it is a subdomain,
    // e.g.: limited.facebook.com
    //        .facebook.com
    //
    // It may make sense to support vice-versa too, but we haven't found any
    // instances of that so far, so leaving it only-way only for
    // facebook-like cases.
    if (issuer_domain != constraint_domain)
    {
      const auto pattern = "." + constraint_domain;
      return issuer_domain.ends_with(pattern);
    }

    return true;
  }

  static void remove_jwt_public_signing_keys(
    ccf::kv::Tx& tx, std::string issuer)
  {
    auto keys = tx.rw<JwtPublicSigningKeysMetadata>(
      Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);

    keys->foreach([&issuer, &keys](const auto& k, const auto& v) {
      auto it = find_if(v.begin(), v.end(), [&](const auto& metadata) {
        return metadata.issuer == issuer;
      });

      if (it != v.end())
      {
        std::vector<OpenIDJWKMetadata> updated(v.begin(), it);
        updated.insert(updated.end(), ++it, v.end());

        if (!updated.empty())
        {
          keys->put(k, updated);
        }
        else
        {
          keys->remove(k);
        }
      }
      return true;
    });
  }

  static bool set_jwt_public_signing_keys(
    ccf::kv::Tx& tx,
    const std::string& log_prefix,
    std::string issuer,
    const JwtIssuerMetadata& issuer_metadata,
    const JsonWebKeySet& jwks)
  {
    auto keys = tx.rw<JwtPublicSigningKeysMetadata>(
      Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);
    // add keys
    if (jwks.keys.empty())
    {
      LOG_FAIL_FMT("{}: JWKS has no keys", log_prefix);
      return false;
    }
    std::map<std::string, PublicKey> new_keys;
    std::map<std::string, JwtIssuer> issuer_constraints;

    try
    {
      for (auto& jwk : jwks.keys)
      {
        if (!jwk.kid.has_value())
        {
          throw std::logic_error("Missing kid for JWT signing key");
        }

        const auto& kid = jwk.kid.value();
        auto key_der = try_parse_jwk(jwk);

        if (jwk.issuer)
        {
          if (!check_issuer_constraint(issuer, *jwk.issuer))
          {
            throw std::logic_error(fmt::format(
              "JWKS kid {} with issuer constraint {} fails validation "
              "against "
              "issuer {}",
              kid,
              *jwk.issuer,
              issuer));
          }

          issuer_constraints.emplace(kid, *jwk.issuer);
        }

        new_keys.emplace(kid, key_der);
      }
    }
    catch (const std::exception& exc)
    {
      LOG_FAIL_FMT("{}: {}", log_prefix, exc.what());
      return false;
    }

    if (new_keys.empty())
    {
      LOG_FAIL_FMT("{}: no keys left after applying filter", log_prefix);
      return false;
    }

    std::set<std::string> existing_kids;
    keys->foreach([&existing_kids, &issuer](const auto& k, const auto& v) {
      if (find_if(v.begin(), v.end(), [&](const auto& metadata) {
            return metadata.issuer == issuer;
          }) != v.end())
      {
        existing_kids.insert(k);
      }

      return true;
    });

    for (auto& [kid, der] : new_keys)
    {
      OpenIDJWKMetadata value{
        .public_key = der, .issuer = issuer, .constraint = std::nullopt};
      value.public_key = der;

      const auto it = issuer_constraints.find(kid);
      if (it != issuer_constraints.end())
      {
        value.constraint = it->second;
      }

      if (existing_kids.count(kid))
      {
        const auto& keys_for_kid = keys->get(kid);
        if (
          find_if(
            keys_for_kid->begin(),
            keys_for_kid->end(),
            [&value](const auto& metadata) {
              return metadata.public_key == value.public_key &&
                metadata.issuer == value.issuer &&
                metadata.constraint == value.constraint;
            }) != keys_for_kid->end())
        {
          // Avoid redundant writes. Thus, preserve the behaviour from #5027.
          continue;
        }
      }

      LOG_DEBUG_FMT(
        "Save JWT key kid={} issuer={}, constraint={}",
        kid,
        value.issuer,
        value.constraint);

      auto existing_keys = keys->get(kid);
      if (existing_keys)
      {
        const auto prev = find_if(
          existing_keys->begin(),
          existing_keys->end(),
          [&](const auto& issuer_with_constraint) {
            return issuer_with_constraint.issuer == issuer;
          });

        if (prev != existing_keys->end())
        {
          *prev = value;
        }
        else
        {
          existing_keys->push_back(std::move(value));
        }
        keys->put(kid, *existing_keys);
      }
      else
      {
        keys->put(kid, std::vector<OpenIDJWKMetadata>{value});
      }
    }

    for (auto& kid : existing_kids)
    {
      if (!new_keys.contains(kid))
      {
        auto updated = keys->get(kid);
        updated->erase(
          std::remove_if(
            updated->begin(),
            updated->end(),
            [&](const auto& metadata) { return metadata.issuer == issuer; }),
          updated->end());

        if (updated->empty())
        {
          keys->remove(kid);
        }
        else
        {
          keys->put(kid, *updated);
        }
      }
    }

    return true;
  }
}