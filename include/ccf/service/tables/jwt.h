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
  enum class JwtIssuerKeyFilter : uint8_t
  {
    All
  };

  DECLARE_JSON_ENUM(JwtIssuerKeyFilter, {{JwtIssuerKeyFilter::All, "all"}});

  struct JwtIssuerMetadata
  {
    /// Optional CA bundle name used for authentication when auto-refreshing
    std::optional<std::string> ca_cert_bundle_name;
    /// Whether to auto-refresh keys from the issuer
    bool auto_refresh = false;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JwtIssuerMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(JwtIssuerMetadata);
  DECLARE_JSON_OPTIONAL_FIELDS(
    JwtIssuerMetadata, ca_cert_bundle_name, auto_refresh);

  using JwtIssuer = std::string;
  using JwtKeyId = std::string;
  using Cert = std::vector<uint8_t>;
  using ECPublicKey = std::vector<uint8_t>;

  struct OpenIDJWKMetadata
  {
    ECPublicKey public_key;
    JwtIssuer issuer;
    std::optional<JwtIssuer> constraint;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(OpenIDJWKMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(OpenIDJWKMetadata, issuer, public_key);
  DECLARE_JSON_OPTIONAL_FIELDS(OpenIDJWKMetadata, constraint);

  using JwtPublicSigningKeysMetadata =
    ServiceMap<JwtKeyId, std::vector<OpenIDJWKMetadata>>;

  struct OpenIDJWKMetadataLegacy
  {
    Cert cert;
    JwtIssuer issuer;
    std::optional<JwtIssuer> constraint;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(OpenIDJWKMetadataLegacy);
  DECLARE_JSON_REQUIRED_FIELDS(OpenIDJWKMetadataLegacy, issuer, cert);
  DECLARE_JSON_OPTIONAL_FIELDS(OpenIDJWKMetadataLegacy, constraint);

  using JwtPublicSigningKeysMetadataLegacy =
    ServiceMap<JwtKeyId, std::vector<OpenIDJWKMetadataLegacy>>;

  using JwtIssuers = ServiceMap<JwtIssuer, JwtIssuerMetadata>;

  namespace Tables
  {
    static constexpr auto JWT_ISSUERS = "public:ccf.gov.jwt.issuers";

    static constexpr auto JWT_PUBLIC_SIGNING_KEYS_METADATA =
      "public:ccf.gov.jwt.public_signing_keys_metadata_v2";

    namespace Legacy
    {
      static constexpr auto JWT_PUBLIC_SIGNING_KEYS =
        "public:ccf.gov.jwt.public_signing_key";
      static constexpr auto JWT_PUBLIC_SIGNING_KEY_ISSUER =
        "public:ccf.gov.jwt.public_signing_key_issuer";
      static constexpr auto JWT_PUBLIC_SIGNING_KEYS_METADATA =
        "public:ccf.gov.jwt.public_signing_keys_metadata";

      using JwtPublicSigningKeys =
        ccf::kv::RawCopySerialisedMap<JwtKeyId, Cert>;
      using JwtPublicSigningKeyIssuer =
        ccf::kv::RawCopySerialisedMap<JwtKeyId, JwtIssuer>;
    }
  }

  struct JsonWebKeySet
  {
    std::vector<ccf::crypto::JsonWebKeyData> keys;

    bool operator!=(const JsonWebKeySet& rhs) const
    {
      return keys != rhs.keys;
    }
  };
  DECLARE_JSON_TYPE(JsonWebKeySet)
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeySet, keys)
}
