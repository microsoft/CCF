// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/proposals.h"
#include "ccf/tx.h"
#include "http/http_jwt.h"

#include <set>
#include <sstream>

namespace ccf
{
  static void legacy_remove_jwt_public_signing_keys(
    ccf::kv::Tx& tx, std::string issuer)
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

  static bool check_issuer_constraint(
    const std::string& issuer, const std::string& constraint)
  {
    // Only accept key constraints for the same (sub)domain. This is to avoid
    // setting keys from issuer A which will be used to validate iss claims for
    // issuer B, so this doesn't make sense (at least for now).

    const auto issuer_domain = ::http::parse_url_full(issuer).host;
    const auto constraint_domain = ::http::parse_url_full(constraint).host;

    if (constraint_domain.empty())
    {
      return false;
    }

    // Either constraint's domain == issuer's domain or it is a subdomain, e.g.:
    // limited.facebook.com
    //        .facebook.com
    //
    // It may make sense to support vice-versa too, but we haven't found any
    // instances of that so far, so leaveing it only-way only for facebook-like
    // cases.
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
    // Unlike resetting JWT keys for a particular issuer, removing keys can be
    // safely done on both table revisions, as soon as the application shouldn't
    // use them anyway after being ask about that explicitly.
    legacy_remove_jwt_public_signing_keys(tx, issuer);

    auto keys =
      tx.rw<JwtPublicSigningKeys>(Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);

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
    auto keys =
      tx.rw<JwtPublicSigningKeys>(Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);
    // add keys
    if (jwks.keys.empty())
    {
      LOG_FAIL_FMT("{}: JWKS has no keys", log_prefix);
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
        der = ccf::crypto::raw_from_b64(der_base64);
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

      try
      {
        ccf::crypto::make_unique_verifier(
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

      LOG_INFO_FMT("{}: Storing JWT signing key with kid {}", log_prefix, kid);
      new_keys.emplace(kid, der);

      if (jwk.issuer)
      {
        if (!check_issuer_constraint(issuer, *jwk.issuer))
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
    keys->foreach([&existing_kids, &issuer_constraints, &issuer](
                    const auto& k, const auto& v) {
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
      OpenIDJWKMetadata value{der, issuer, std::nullopt};
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
              return metadata.cert == value.cert &&
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