// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/jwk.h"
#include "ccf/ds/json.h"
#include "ccf/service/map.h"

#include <map>
#include <optional>
#include <string>

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
  using Cert = std::vector<uint8_t>;

  using JwtIssuers = ServiceMap<JwtIssuer, JwtIssuerMetadata>;
  using JwtPublicSigningKeys = kv::RawCopySerialisedMap<JwtKeyId, Cert>;
  using JwtPublicSigningKeyIssuer =
    kv::RawCopySerialisedMap<JwtKeyId, JwtIssuer>;

  namespace Tables
  {
    static constexpr auto JWT_ISSUERS = "public:ccf.gov.jwt.issuers";
    static constexpr auto JWT_PUBLIC_SIGNING_KEYS =
      "public:ccf.gov.jwt.public_signing_keys";
    static constexpr auto JWT_PUBLIC_SIGNING_KEY_ISSUER =
      "public:ccf.gov.jwt.public_signing_key_issuer";
  }

  struct JsonWebKeySet
  {
    std::vector<crypto::JsonWebKey> keys;

    bool operator!=(const JsonWebKeySet& rhs) const
    {
      return keys != rhs.keys;
    }
  };
  DECLARE_JSON_TYPE(JsonWebKeySet)
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeySet, keys)
}
