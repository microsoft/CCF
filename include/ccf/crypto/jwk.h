// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/ds/json.h"

#include <string>

namespace crypto
{
  enum class JsonWebKeyType
  {
    EC = 0,
    RSA = 1
  };
  DECLARE_JSON_ENUM(
    JsonWebKeyType, {{JsonWebKeyType::EC, "EC"}, {JsonWebKeyType::RSA, "RSA"}});

  // TODO: Refactor with existing JWT stuff
  struct JsonWebKeyBase
  {
    JsonWebKeyType kty;
    std::optional<std::string> kid = std::nullopt;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JsonWebKeyBase);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyBase, kty);
  DECLARE_JSON_OPTIONAL_FIELDS(JsonWebKeyBase, kid);

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

  static JsonWebKeyECCurve curve_id_to_jwk_curve(CurveID curve_id)
  {
    switch (curve_id)
    {
      case CurveID::SECP384R1:
        return JsonWebKeyECCurve::P384;
      case CurveID::SECP256R1:
        return JsonWebKeyECCurve::P256;
      default:
      {
        throw std::logic_error(fmt::format("Unknown curve {}", curve_id));
      }
    }
  }

  struct JsonWebKeyEC : JsonWebKeyBase
  {
    JsonWebKeyECCurve crv;
    std::string x; // base64url encoded
    std::string y; // base64url encoded
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyEC, JsonWebKeyBase);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyEC, crv, x, y);

  // enum class JsonWebKeyRSAAlg
  // {
  //   P256 = 0,
  //   P384 = 1,
  //   P521 = 2
  // };
  // DECLARE_JSON_ENUM(
  //   JsonWebKeyECCurve,
  //   {{JsonWebKeyECCurve::P256, "P-256"},
  //    {JsonWebKeyECCurve::P384, "P-384"},
  //    {JsonWebKeyECCurve::P521, "P-521"}});

  struct JsonWebKeyRSA : JsonWebKeyBase
  {
    std::string alg;
    std::string n; // base64url encoded
    std::string e; // base64url encoded
  };
  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(
    JsonWebKeyRSA, JsonWebKeyBase);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyRSA, n, e);
  DECLARE_JSON_OPTIONAL_FIELDS(JsonWebKeyRSA, alg);
}