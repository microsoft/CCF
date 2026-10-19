// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/did_key.h"

#include "ccf/crypto/openssl/openssl_wrappers.h"

#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdexcept>

namespace ccf::crypto
{
  namespace
  {
    using namespace OpenSSL;
    constexpr std::string_view BASE58 =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    constexpr std::string_view PREFIX = "did:key:z";
    constexpr size_t MAX_DID_SIZE = 3000;
    constexpr int MAX_RSA_BITS = 16384;

    bool same_public_key(EVP_PKEY* lhs, EVP_PKEY* rhs)
    {
      const auto rc = EVP_PKEY_eq(lhs, rhs);
      if (rc < -1)
      {
        throw std::runtime_error(
          "Failed to compare public keys: " + first_error());
      }
      return rc == 1;
    }

    [[noreturn]] void invalid_key()
    {
      throw std::invalid_argument(
        "Invalid did:key public key: " + first_error());
    }

    Unique_PKEY parse_public_key(std::span<const uint8_t> der)
    {
      if (der.empty() || der.size() > MAX_DID_SIZE)
      {
        throw std::invalid_argument("Invalid public key length");
      }
      const auto* p = der.data();
      auto* key = d2i_PUBKEY(nullptr, &p, der.size());
      Unique_PKEY result(key, EVP_PKEY_free, false);
      if (key == nullptr || p != der.data() + der.size())
      {
        invalid_key();
      }
      return result;
    }

    void validate_public_key(EVP_PKEY* key)
    {
      Unique_EVP_PKEY_CTX ctx(key);
      if (EVP_PKEY_public_check(ctx) != 1)
      {
        invalid_key();
      }
      if (
        EVP_PKEY_is_a(key, "RSA") != 0 &&
        (EVP_PKEY_get_bits(key) < 2048 ||
         EVP_PKEY_get_bits(key) > MAX_RSA_BITS))
      {
        throw std::invalid_argument(
          "did:key RSA keys must be between 2048 and 16384 bits");
      }
    }

    std::string encode_base58(std::span<const uint8_t> bytes)
    {
      Unique_BIGNUM value;
      CHECKNULL(BN_bin2bn(bytes.data(), bytes.size(), value));
      std::string result;
      while (BN_is_zero(value) == 0)
      {
        const auto digit = BN_div_word(value, 58);
        if (digit == static_cast<BN_ULONG>(-1))
        {
          throw std::runtime_error("Failed to encode base58: " + first_error());
        }
        result.push_back(BASE58[digit]);
      }
      for (auto b : bytes)
      {
        if (b != 0)
        {
          break;
        }
        result.push_back('1');
      }
      std::reverse(result.begin(), result.end());
      return result;
    }

    std::vector<uint8_t> decode_base58(std::string_view text)
    {
      Unique_BIGNUM value;
      for (auto c : text)
      {
        const auto digit = BASE58.find(c);
        if (digit == std::string_view::npos)
        {
          throw std::invalid_argument("Invalid base58btc character");
        }
        CHECK1(BN_mul_word(value, 58));
        CHECK1(BN_add_word(value, digit));
      }
      const auto zeros = text.find_first_not_of('1');
      const auto leading_zeros =
        zeros == std::string_view::npos ? text.size() : zeros;
      std::vector<uint8_t> result(leading_zeros + BN_num_bytes(value));
      CHECKEQUAL(
        BN_num_bytes(value), BN_bn2bin(value, result.data() + leading_zeros));
      return result;
    }

    std::vector<uint8_t> serialise_public_key(EVP_PKEY* key)
    {
      const auto size = i2d_PUBKEY(key, nullptr);
      CHECKPOSITIVE(size);
      std::vector<uint8_t> result(size);
      auto* p = result.data();
      CHECKEQUAL(size, i2d_PUBKEY(key, &p));
      return result;
    }
  }

  std::string did_key_from_public_key_der(std::span<const uint8_t> der)
  {
    using namespace OpenSSL;
    auto key = parse_public_key(der);
    validate_public_key(key);
    std::vector<uint8_t> encoded;
    if (EVP_PKEY_is_a(key, "EC") != 0)
    {
      char group[80] = {};
      size_t length = 0;
      CHECK1(EVP_PKEY_get_utf8_string_param(
        key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &length));
      const auto nid = OBJ_txt2nid(group);
      size_t coordinate_size = 0;
      if (nid == NID_X9_62_prime256v1)
      {
        encoded = {0x80, 0x24};
        coordinate_size = 32;
      }
      else if (nid == NID_secp384r1)
      {
        encoded = {0x81, 0x24};
        coordinate_size = 48;
      }
      else if (nid == NID_secp521r1)
      {
        encoded = {0x82, 0x24};
        coordinate_size = 66;
      }
      else
      {
        throw std::invalid_argument("Unsupported did:key EC curve");
      }
      BIGNUM* x_raw = nullptr;
      BIGNUM* y_raw = nullptr;
      CHECK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x_raw));
      Unique_BIGNUM x(x_raw, BN_free);
      CHECK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y_raw));
      Unique_BIGNUM y(y_raw, BN_free);
      encoded.push_back(BN_is_odd(y) != 0 ? 3 : 2);
      encoded.resize(3 + coordinate_size);
      CHECKEQUAL(
        coordinate_size, BN_bn2binpad(x, encoded.data() + 3, coordinate_size));
    }
    else if (EVP_PKEY_is_a(key, "RSA") != 0)
    {
      encoded = {0x85, 0x24};
      const auto size = i2d_PublicKey(key, nullptr);
      CHECKPOSITIVE(size);
      encoded.resize(2 + size);
      auto* p = encoded.data() + 2;
      CHECKEQUAL(size, i2d_PublicKey(key, &p));
    }
    else
    {
      throw std::invalid_argument("Unsupported did:key public key type");
    }
    return std::string(PREFIX) + encode_base58(encoded);
  }

  std::vector<uint8_t> public_key_der_from_did_key(std::string_view id)
  {
    using namespace OpenSSL;
    if (
      !id.starts_with(PREFIX) || id.size() <= PREFIX.size() ||
      id.size() > MAX_DID_SIZE)
    {
      throw std::invalid_argument("Invalid did:key prefix or length");
    }
    const auto encoded = decode_base58(id.substr(PREFIX.size()));
    if (encoded.size() < 3 || encoded[1] != 0x24)
    {
      throw std::invalid_argument("Unsupported did:key multicodec");
    }
    const auto bytes = std::span(encoded).subspan(2);
    EVP_PKEY* raw = nullptr;
    if (encoded[0] == 0x85)
    {
      const auto* p = bytes.data();
      raw = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, bytes.size());
      Unique_PKEY key(raw, EVP_PKEY_free, false);
      if (raw == nullptr || p != bytes.data() + bytes.size())
      {
        invalid_key();
      }
      validate_public_key(key);
      auto der = serialise_public_key(key);
      if (did_key_from_public_key_der(der) != id)
      {
        throw std::invalid_argument("Noncanonical did:key");
      }
      return der;
    }
    const char* group = nullptr;
    size_t size = 0;
    switch (encoded[0])
    {
      case 0x80:
      {
        group = "prime256v1";
        size = 33;
        break;
      }
      case 0x81:
      {
        group = "secp384r1";
        size = 49;
        break;
      }
      case 0x82:
      {
        group = "secp521r1";
        size = 67;
        break;
      }
      default:
      {
        throw std::invalid_argument("Unsupported did:key multicodec");
      }
    }
    if (bytes.size() != size || (bytes[0] != 2 && bytes[0] != 3))
    {
      throw std::invalid_argument("Invalid did:key EC point encoding");
    }
    Unique_EVP_PKEY_CTX ctx("EC");
    CHECK1(EVP_PKEY_fromdata_init(ctx));
    OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group), 0),
      OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY,
        const_cast<uint8_t*>(bytes.data()),
        bytes.size()),
      OSSL_PARAM_construct_end()};
    const auto rc = EVP_PKEY_fromdata(ctx, &raw, EVP_PKEY_PUBLIC_KEY, params);
    Unique_PKEY key(raw, EVP_PKEY_free, false);
    if (rc != 1 || raw == nullptr)
    {
      invalid_key();
    }
    validate_public_key(key);
    auto der = serialise_public_key(key);
    if (did_key_from_public_key_der(der) != id)
    {
      throw std::invalid_argument("Noncanonical did:key");
    }
    return der;
  }

  bool public_keys_equal(const Pem& lhs, const Pem& rhs)
  {
    using namespace OpenSSL;
    Unique_BIO left(lhs);
    Unique_BIO right(rhs);
    Unique_PKEY left_key(left);
    Unique_PKEY right_key(right);
    return same_public_key(left_key, right_key);
  }

  bool certs_have_same_public_key(
    std::span<const uint8_t> lhs, std::span<const uint8_t> rhs)
  {
    using namespace OpenSSL;
    const auto* l = lhs.data();
    const auto* r = rhs.data();
    Unique_X509 left(d2i_X509(nullptr, &l, lhs.size()), X509_free);
    Unique_X509 right(d2i_X509(nullptr, &r, rhs.size()), X509_free);
    return same_public_key(X509_get0_pubkey(left), X509_get0_pubkey(right));
  }
}
