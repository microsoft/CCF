// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/cose_key.h"

#include "ccf/crypto/base64.h"
#include "crypto/openssl/cose_verifier.h"
#include "crypto/openssl/ec_public_key.h"

#include <bit>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tav/cbor.hpp>
#include <utility>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace
{
  using namespace ccf::crypto;
  using tav::cbor::Kind;
  using tav::cbor::Value;

  // COSE_Key labels, from RFC 9052 Section 7.1, RFC 9053 Section 7.1.1 and
  // RFC 8230 Section 4
  constexpr int64_t LABEL_KTY = 1;
  constexpr int64_t LABEL_KID = 2;
  constexpr int64_t LABEL_ALG = 3;
  constexpr int64_t LABEL_KEY_OPS = 4;
  constexpr int64_t LABEL_EC2_CRV = -1;
  constexpr int64_t LABEL_EC2_X = -2;
  constexpr int64_t LABEL_EC2_Y = -3;
  constexpr int64_t LABEL_EC2_D = -4;
  constexpr int64_t LABEL_RSA_N = -1;
  constexpr int64_t LABEL_RSA_E = -2;
  // d, p, q, dP, dQ, qInv, other, r_i, d_i and t_i
  constexpr int64_t LABEL_RSA_PRIVATE_FIRST = -12;
  constexpr int64_t LABEL_RSA_PRIVATE_LAST = -3;

  constexpr int64_t KEY_OP_VERIFY = 2;

  // COSE elliptic curves, from RFC 9053 Section 7.1
  constexpr int64_t CRV_P256 = 1;
  constexpr int64_t CRV_P384 = 2;
  constexpr int64_t CRV_P521 = 3;

  // RFC 8230 Section 6.1 requires at least 2048 bits. The upper bound, also
  // OpenSSL's, limits the cost of verifying with a supplied key.
  constexpr size_t RSA_MIN_MODULUS_BITS = 2048;
  constexpr size_t RSA_MAX_MODULUS_BITS = 16384;
  // OpenSSL's bound on e for moduli above 3072 bits. It also limits the cost of
  // verifying with smaller moduli, and keeps e below n.
  constexpr size_t RSA_MAX_EXPONENT_SIZE = 8;

  constexpr uint8_t SEC1_UNCOMPRESSED_POINT = 0x04;

  [[noreturn]] void invalid(std::string_view reason)
  {
    throw std::invalid_argument(fmt::format("Invalid COSE_Key: {}", reason));
  }

  int64_t cose_crv(CurveID curve)
  {
    switch (curve)
    {
      case CurveID::SECP256R1:
        return CRV_P256;
      case CurveID::SECP384R1:
        return CRV_P384;
      case CurveID::SECP521R1:
        return CRV_P521;
      case CurveID::NONE:
      case CurveID::CURVE25519:
      case CurveID::X25519:
      default:
        throw std::runtime_error(
          fmt::format("Curve {} has no COSE EC2 identifier", curve));
    }
  }

  struct COSECurve
  {
    CurveID id = CurveID::NONE;
    size_t coordinate_size = 0;
  };

  COSECurve curve_from_cose_crv(int64_t crv)
  {
    switch (crv)
    {
      case CRV_P256:
        return {.id = CurveID::SECP256R1, .coordinate_size = 32};
      case CRV_P384:
        return {.id = CurveID::SECP384R1, .coordinate_size = 48};
      case CRV_P521:
        return {.id = CurveID::SECP521R1, .coordinate_size = 66};
      default:
        invalid(fmt::format("unsupported crv {}", crv));
    }
  }

  std::vector<uint8_t> encode_cose_key(
    COSEKeyType kty,
    std::vector<tav::cbor::MapItem>&& items,
    std::optional<int64_t> alg,
    std::optional<std::span<const uint8_t>> kid)
  {
    using namespace tav::cbor;
    items.emplace_back(
      make_signed(LABEL_KTY), make_signed(static_cast<int64_t>(kty)));
    if (kid.has_value())
    {
      items.emplace_back(make_signed(LABEL_KID), make_bytes(kid.value()));
    }
    if (alg.has_value())
    {
      items.emplace_back(make_signed(LABEL_ALG), make_signed(alg.value()));
    }
    return make_map(std::move(items)).det_serialize();
  }

  std::vector<uint8_t> encode_cose_key(
    const COSEKey::EC2Parameters& parameters,
    std::optional<int64_t> alg,
    std::optional<std::span<const uint8_t>> kid)
  {
    using namespace tav::cbor;
    std::vector<MapItem> items;
    items.emplace_back(make_signed(LABEL_EC2_CRV), make_signed(parameters.crv));
    items.emplace_back(make_signed(LABEL_EC2_X), make_bytes(parameters.x));
    items.emplace_back(make_signed(LABEL_EC2_Y), make_bytes(parameters.y));
    return encode_cose_key(COSEKeyType::EC2, std::move(items), alg, kid);
  }

  std::vector<uint8_t> encode_cose_key(
    const COSEKey::RSAParameters& parameters,
    std::optional<int64_t> alg,
    std::optional<std::span<const uint8_t>> kid)
  {
    using namespace tav::cbor;
    std::vector<MapItem> items;
    items.emplace_back(make_signed(LABEL_RSA_N), make_bytes(parameters.n));
    items.emplace_back(make_signed(LABEL_RSA_E), make_bytes(parameters.e));
    return encode_cose_key(COSEKeyType::RSA, std::move(items), alg, kid);
  }

  COSEKey::EC2Parameters parameters_of(const ECPublicKey& key)
  {
    auto coordinates = key.coordinates();
    return {
      .crv = cose_crv(key.get_curve_id()),
      .x = std::move(coordinates.x),
      .y = std::move(coordinates.y)};
  }

  COSEKey::RSAParameters parameters_of(const RSAPublicKey& key)
  {
    const auto jwk = key.public_key_jwk();
    return {.n = raw_from_b64url(jwk.n), .e = raw_from_b64url(jwk.e)};
  }

  std::vector<uint8_t> encode_cose_key(
    const std::variant<ECPublicKeyPtr, RSAPublicKeyPtr>& key,
    std::optional<int64_t> alg,
    std::optional<std::span<const uint8_t>> kid)
  {
    return std::visit(
      [&](const auto& typed) {
        return encode_cose_key(parameters_of(*typed), alg, kid);
      },
      key);
  }

  template <typename T>
  const T& non_null(const std::shared_ptr<T>& key)
  {
    if (key == nullptr)
    {
      throw std::invalid_argument("COSEKey requires a key");
    }
    return *key;
  }

  std::optional<Value> find_label(const Value& map, int64_t label)
  {
    const auto size = map.size();
    for (size_t i = 0; i < size; ++i)
    {
      const auto key = map.map_key_at(i);
      if (key.kind() == Kind::SIGNED && key.as_signed() == label)
      {
        return map.map_value_at(i);
      }
    }
    return std::nullopt;
  }

  bool has_private_rsa_parts(const Value& map)
  {
    const auto size = map.size();
    for (size_t i = 0; i < size; ++i)
    {
      const auto key = map.map_key_at(i);
      if (
        key.kind() == Kind::SIGNED &&
        key.as_signed() >= LABEL_RSA_PRIVATE_FIRST &&
        key.as_signed() <= LABEL_RSA_PRIVATE_LAST)
      {
        return true;
      }
    }
    return false;
  }

  int64_t require_int(const Value& value, std::string_view name)
  {
    if (value.kind() != Kind::SIGNED)
    {
      invalid(fmt::format("{} must be an integer", name));
    }
    return value.as_signed();
  }

  std::vector<uint8_t> require_bytes(
    const Value& map, int64_t label, std::string_view name)
  {
    const auto value = find_label(map, label);
    if (!value.has_value())
    {
      invalid(fmt::format("{} is missing", name));
    }
    if (value.value().kind() != Kind::BYTES)
    {
      invalid(fmt::format("{} must be a byte string", name));
    }
    const auto bytes = value.value().as_bytes();
    return {bytes.begin(), bytes.end()};
  }

  void check_key_ops(const Value& key_ops)
  {
    if (key_ops.kind() != Kind::ARRAY)
    {
      invalid("key_ops must be an array");
    }
    const auto size = key_ops.size();
    for (size_t i = 0; i < size; ++i)
    {
      const auto op = key_ops.array_at(i);
      if (op.kind() == Kind::SIGNED && op.as_signed() == KEY_OP_VERIFY)
      {
        return;
      }
    }
    invalid("key_ops does not allow verify");
  }

  // Returns kty and alg. kid and key_ops are only checked.
  std::pair<int64_t, std::optional<int64_t>> parse_common(const Value& map)
  {
    const auto kty_value = find_label(map, LABEL_KTY);
    if (!kty_value.has_value())
    {
      invalid("kty is missing");
    }
    const auto kty = require_int(kty_value.value(), "kty");
    const auto kid = find_label(map, LABEL_KID);
    if (kid.has_value() && kid.value().kind() != Kind::BYTES)
    {
      invalid("kid must be a byte string");
    }
    const auto key_ops = find_label(map, LABEL_KEY_OPS);
    if (key_ops.has_value())
    {
      check_key_ops(key_ops.value());
    }
    std::optional<int64_t> alg = std::nullopt;
    const auto alg_value = find_label(map, LABEL_ALG);
    if (alg_value.has_value())
    {
      alg = require_int(alg_value.value(), "alg");
    }
    return {kty, alg};
  }

  ECPublicKeyPtr parse_ec2(const Value& map)
  {
    if (find_label(map, LABEL_EC2_D).has_value())
    {
      invalid("private key parameter d is not accepted");
    }
    const auto crv = find_label(map, LABEL_EC2_CRV);
    if (!crv.has_value())
    {
      invalid("crv is missing");
    }
    COSEKey::EC2Parameters parameters;
    parameters.crv = require_int(crv.value(), "crv");
    const auto curve = curve_from_cose_crv(parameters.crv);
    parameters.x = require_bytes(map, LABEL_EC2_X, "x");
    parameters.y = require_bytes(map, LABEL_EC2_Y, "y");
    if (
      parameters.x.size() != curve.coordinate_size ||
      parameters.y.size() != curve.coordinate_size)
    {
      invalid(fmt::format(
        "x and y must be {} bytes long for crv {}",
        curve.coordinate_size,
        parameters.crv));
    }

    // OpenSSL rejects coordinates that are not below the field prime, and
    // points that are not on the curve.
    std::vector<uint8_t> point;
    point.reserve(1 + parameters.x.size() + parameters.y.size());
    point.push_back(SEC1_UNCOMPRESSED_POINT);
    point.insert(point.end(), parameters.x.begin(), parameters.x.end());
    point.insert(point.end(), parameters.y.begin(), parameters.y.end());
    return std::make_shared<ECPublicKey_OpenSSL>(key_from_raw_ec_point(
      point, ECPublicKey_OpenSSL::get_openssl_group_id(curve.id)));
  }

  std::vector<uint8_t> require_unsigned(
    const Value& map, int64_t label, std::string_view name)
  {
    auto value = require_bytes(map, label, name);
    if (value.empty() || value.front() == 0)
    {
      invalid(fmt::format(
        "{} must be non-empty and have no leading zero octets", name));
    }
    return value;
  }

  // Checks that n and e, big-endian without leading zero octets, form an
  // acceptable RSA key: a modulus of 2048 to 16384 bits, and an odd public
  // exponent, at least 3 and at most 64 bits long. Returns why they do not,
  // or std::nullopt if they do.
  std::optional<std::string> rsa_key_error(
    const COSEKey::RSAParameters& parameters)
  {
    const auto& n = parameters.n;
    const auto& e = parameters.e;
    const size_t modulus_bits = n.empty() ?
      0 :
      ((n.size() - 1) * 8) + static_cast<size_t>(std::bit_width(n.front()));
    if (
      modulus_bits < RSA_MIN_MODULUS_BITS ||
      modulus_bits > RSA_MAX_MODULUS_BITS)
    {
      return fmt::format(
        "n must be {} to {} bits long",
        RSA_MIN_MODULUS_BITS,
        RSA_MAX_MODULUS_BITS);
    }
    // Without leading zero octets, an odd e other than 1 is at least 3
    if (
      e.empty() || e.size() > RSA_MAX_EXPONENT_SIZE || (e.back() & 1U) == 0 ||
      (e.size() == 1 && e.front() == 1))
    {
      return "e must be odd, at least 3 and at most 64 bits long";
    }
    return std::nullopt;
  }

  RSAPublicKeyPtr parse_rsa(const Value& map)
  {
    if (has_private_rsa_parts(map))
    {
      invalid("private key parameters are not accepted");
    }
    COSEKey::RSAParameters parameters;
    parameters.n = require_unsigned(map, LABEL_RSA_N, "n");
    parameters.e = require_unsigned(map, LABEL_RSA_E, "e");
    const auto error = rsa_key_error(parameters);
    if (error.has_value())
    {
      invalid(error.value());
    }
    // The JWK form of the key, which CCF imports
    JsonWebKeyRSAPublic jwk;
    jwk.kty = JsonWebKeyType::RSA;
    jwk.n = b64url_from_raw(parameters.n, false /* with_padding */);
    jwk.e = b64url_from_raw(parameters.e, false /* with_padding */);
    return make_rsa_public_key(jwk);
  }

  void check_alg_matches_key(int64_t alg, const COSEKey& key)
  {
    // Throws for algorithms that CCF cannot verify
    if (!cose_algorithm_matches_key(alg, key))
    {
      throw std::runtime_error(
        fmt::format("COSE algorithm {} does not match the key", alg));
    }
  }
}

namespace ccf::crypto
{
  COSEKey::COSEKey(PublicKey public_key_, std::optional<int64_t> alg_) :
    public_key(std::move(public_key_)),
    key_alg(alg_)
  {}

  COSEKey::COSEKey(ECPublicKeyPtr key) : COSEKey(PublicKey{key}, std::nullopt)
  {
    // Only curves with a COSE identifier
    cose_crv(non_null(key).get_curve_id());
  }

  COSEKey::COSEKey(RSAPublicKeyPtr key) : COSEKey(PublicKey{key}, std::nullopt)
  {
    const auto error = rsa_key_error(parameters_of(non_null(key)));
    if (error.has_value())
    {
      throw std::runtime_error(
        fmt::format("Unsupported COSE RSA key: {}", error.value()));
    }
  }

  COSEKey COSEKey::from_cbor(std::span<const uint8_t> cose_key)
  {
    try
    {
      const auto map = tav::cbor::nondet_parse(cose_key);
      if (map.kind() != Kind::MAP)
      {
        invalid("not a map");
      }
      const auto [kty_value, alg_value] = parse_common(map);
      PublicKey parsed;
      switch (kty_value)
      {
        case static_cast<int64_t>(COSEKeyType::EC2):
          parsed = parse_ec2(map);
          break;
        case static_cast<int64_t>(COSEKeyType::RSA):
          parsed = parse_rsa(map);
          break;
        default:
          invalid(fmt::format("unsupported kty {}", kty_value));
      }
      COSEKey key(std::move(parsed), alg_value);
      // Throws for algorithms that CCF cannot verify
      if (
        alg_value.has_value() &&
        !cose_algorithm_matches_key(alg_value.value(), key))
      {
        invalid(
          fmt::format("alg {} does not match the key", alg_value.value()));
      }
      return key;
    }
    catch (const std::invalid_argument&)
    {
      throw;
    }
    catch (const std::bad_alloc&)
    {
      throw;
    }
    catch (const std::exception& e)
    {
      // Such as CBOR decoding errors, and keys that OpenSSL rejects
      invalid(e.what());
    }
  }

  COSEKey COSEKey::from_der_cert(std::span<const uint8_t> der)
  {
    return cose_key_from_der_cert(der);
  }

  COSEKeyType COSEKey::kty() const
  {
    if (std::holds_alternative<ECPublicKeyPtr>(public_key))
    {
      return COSEKeyType::EC2;
    }
    if (std::holds_alternative<RSAPublicKeyPtr>(public_key))
    {
      return COSEKeyType::RSA;
    }
    throw std::logic_error("Unsupported COSE_Key type");
  }

  std::optional<int64_t> COSEKey::alg() const
  {
    return key_alg;
  }

  std::optional<COSEKey::EC2Parameters> COSEKey::ec2_parameters() const
  {
    const auto* key = std::get_if<ECPublicKeyPtr>(&public_key);
    if (key == nullptr)
    {
      return std::nullopt;
    }
    return parameters_of(**key);
  }

  std::optional<COSEKey::RSAParameters> COSEKey::rsa_parameters() const
  {
    const auto* key = std::get_if<RSAPublicKeyPtr>(&public_key);
    if (key == nullptr)
    {
      return std::nullopt;
    }
    return parameters_of(**key);
  }

  ECPublicKeyPtr COSEKey::ec_public_key() const
  {
    const auto* key = std::get_if<ECPublicKeyPtr>(&public_key);
    return key == nullptr ? nullptr : *key;
  }

  RSAPublicKeyPtr COSEKey::rsa_public_key() const
  {
    const auto* key = std::get_if<RSAPublicKeyPtr>(&public_key);
    return key == nullptr ? nullptr : *key;
  }

  std::vector<uint8_t> COSEKey::to_cbor(int64_t alg) const
  {
    check_alg_matches_key(alg, *this);
    return encode_cose_key(public_key, alg, std::nullopt);
  }

  std::vector<uint8_t> COSEKey::to_cbor(
    int64_t alg, std::span<const uint8_t> kid) const
  {
    check_alg_matches_key(alg, *this);
    return encode_cose_key(public_key, alg, kid);
  }

  std::vector<uint8_t> COSEKey::to_cbor(int64_t alg, std::string_view kid) const
  {
    return to_cbor(
      alg,
      std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(kid.data()), kid.size()));
  }

  Sha256Hash COSEKey::thumbprint_sha256() const
  {
    return Sha256Hash(encode_cose_key(public_key, std::nullopt, std::nullopt));
  }
}
