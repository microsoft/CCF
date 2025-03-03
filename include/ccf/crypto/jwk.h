// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"

#include <string>

namespace ccf::crypto
{
  enum class JsonWebKeyType
  {
    EC = 0,
    RSA = 1,
    OKP = 2
  };
  DECLARE_JSON_ENUM(
    JsonWebKeyType,
    {{JsonWebKeyType::EC, "EC"},
     {JsonWebKeyType::RSA, "RSA"},
     {JsonWebKeyType::OKP, "OKP"}});

  struct JsonWebKey
  {
    JsonWebKeyType kty;
    std::optional<std::string> kid = std::nullopt;
    std::optional<std::vector<std::string>> x5c = std::nullopt;

    bool operator==(const JsonWebKey&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JsonWebKey);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKey, kty);
  DECLARE_JSON_OPTIONAL_FIELDS(JsonWebKey, kid, x5c);

  enum class JsonWebKeyECCurve
  {
    P256 = 0,
    P384 = 1,
    P521 = 2
  };
  DECLARE_JSON_ENUM(
    JsonWebKeyECCurve,
    {{JsonWebKeyECCurve::P256, "P-256"},
     {JsonWebKeyECCurve::P384, "P-384"},
     {JsonWebKeyECCurve::P521, "P-521"}});

  struct JsonWebKeyData
  {
    JsonWebKeyType kty;
    std::optional<std::string> kid = std::nullopt;
    std::optional<std::vector<std::string>> x5c = std::nullopt;
    std::optional<std::string> n = std::nullopt;
    std::optional<std::string> e = std::nullopt;
    std::optional<std::string> x = std::nullopt;
    std::optional<std::string> y = std::nullopt;
    std::optional<JsonWebKeyECCurve> crv = std::nullopt;
    std::optional<std::string> issuer = std::nullopt;

    bool operator==(const JsonWebKeyData&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JsonWebKeyData);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyData, kty);
  DECLARE_JSON_OPTIONAL_FIELDS(
    JsonWebKeyData, kid, x5c, n, e, x, y, crv, issuer);

  static JsonWebKeyECCurve curve_id_to_jwk_curve(CurveID curve_id)
  {
    switch (curve_id)
    {
      case CurveID::SECP384R1:
        return JsonWebKeyECCurve::P384;
      case CurveID::SECP256R1:
        return JsonWebKeyECCurve::P256;
      default:
        throw std::logic_error(fmt::format("Unknown curve {}", curve_id));
    }
  }

  static CurveID jwk_curve_to_curve_id(JsonWebKeyECCurve jwk_curve)
  {
    switch (jwk_curve)
    {
      case JsonWebKeyECCurve::P384:
        return CurveID::SECP384R1;
      case JsonWebKeyECCurve::P256:
        return CurveID::SECP256R1;
      default:
        throw std::logic_error(fmt::format("Unknown JWK curve {}", jwk_curve));
    }
  }

  enum class JsonWebKeyEdDSACurve
  {
    ED25519 = 0,
    X25519 = 1
  };
  DECLARE_JSON_ENUM(
    JsonWebKeyEdDSACurve,
    {{JsonWebKeyEdDSACurve::ED25519, "Ed25519"},
     {JsonWebKeyEdDSACurve::X25519, "X25519"}});

  static JsonWebKeyEdDSACurve curve_id_to_jwk_eddsa_curve(CurveID curve_id)
  {
    switch (curve_id)
    {
      case CurveID::CURVE25519:
        return JsonWebKeyEdDSACurve::ED25519;
      case CurveID::X25519:
        return JsonWebKeyEdDSACurve::X25519;
      default:
        throw std::logic_error(fmt::format("Unknown EdDSA curve {}", curve_id));
    }
  }

  struct JsonWebKeyECPublic : JsonWebKey
  {
    JsonWebKeyECCurve crv;
    std::string x; // base64url
    std::string y; // base64url

    bool operator==(const JsonWebKeyECPublic&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyECPublic, JsonWebKey);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyECPublic, crv, x, y);

  struct JsonWebKeyECPrivate : JsonWebKeyECPublic
  {
    std::string d; // base64url

    bool operator==(const JsonWebKeyECPrivate&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyECPrivate, JsonWebKeyECPublic);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyECPrivate, d);

  struct JsonWebKeyRSAPublic : JsonWebKey
  {
    std::string n; // base64url
    std::string e; // base64url

    bool operator==(const JsonWebKeyRSAPublic&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyRSAPublic, JsonWebKey);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyRSAPublic, n, e);

  struct JsonWebKeyRSAPrivate : JsonWebKeyRSAPublic
  {
    std::string d; // base64url
    std::string p; // base64url
    std::string q; // base64url
    std::string dp; // base64url
    std::string dq; // base64url
    std::string qi; // base64url

    bool operator==(const JsonWebKeyRSAPrivate&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyRSAPrivate, JsonWebKeyRSAPublic);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyRSAPrivate, d, p, q, dp, dq, qi);

  struct JsonWebKeyEdDSAPublic : JsonWebKey
  {
    JsonWebKeyEdDSACurve crv;
    std::string x; // base64url

    bool operator==(const JsonWebKeyEdDSAPublic&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyEdDSAPublic, JsonWebKey);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyEdDSAPublic, crv, x);

  struct JsonWebKeyEdDSAPrivate : JsonWebKeyEdDSAPublic
  {
    std::string d; // base64url

    bool operator==(const JsonWebKeyEdDSAPrivate&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyEdDSAPrivate, JsonWebKeyEdDSAPublic);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyEdDSAPrivate, d);
}