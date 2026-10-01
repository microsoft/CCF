// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <openssl/opensslv.h>

static_assert(
  OPENSSL_VERSION_PREREQ(3, 5), "ML-DSA tests require OpenSSL 3.5 or newer");

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/mldsa_key_pair.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/ds/hex.h"
#include "crypto/openssl/mldsa.h"
#include "crypto/openssl/mldsa_key_pair.h"
#include "crypto/test/mldsa_vectors.h"

#include <array>
#include <doctest/doctest.h>
#include <future>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <type_traits>

using namespace ccf::crypto;

namespace
{
  struct ParameterSetInfo
  {
    MLDSAParameterSet id;
    const char* name;
    int nid;
    // FIPS 204 table 2: expanded private key and signature sizes; s2 offset
    // within skEncode follows rho (32), K (32), tr (64) and l packed s1
    // polynomials. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
    size_t expanded_key_size;
    size_t s2_offset;
    size_t signature_size;
  };

  constexpr std::array PARAMETER_SETS = {
    ParameterSetInfo{
      MLDSAParameterSet::ML_DSA_44,
      LN_ML_DSA_44,
      NID_ML_DSA_44,
      2560,
      512,
      2420},
    ParameterSetInfo{
      MLDSAParameterSet::ML_DSA_65,
      LN_ML_DSA_65,
      NID_ML_DSA_65,
      4032,
      768,
      3309},
    ParameterSetInfo{
      MLDSAParameterSet::ML_DSA_87,
      LN_ML_DSA_87,
      NID_ML_DSA_87,
      4896,
      800,
      4627},
  };

  const ParameterSetInfo& info_for(MLDSAParameterSet id)
  {
    for (const auto& info : PARAMETER_SETS)
    {
      if (info.id == id)
      {
        return info;
      }
    }
    throw std::logic_error("Unknown parameter set in test table");
  }
  constexpr size_t MAX_CONTEXT_BYTES = 255;

  constexpr std::array<uint8_t, 7> message = {0, 1, 2, 127, 128, 254, 255};
  constexpr std::array<uint8_t, 4> context = {0, 65, 0, 255};

  static_assert(!std::is_copy_constructible_v<MLDSAPublicKey_OpenSSL>);
  static_assert(!std::is_copy_assignable_v<MLDSAPublicKey_OpenSSL>);
  static_assert(!std::is_copy_constructible_v<MLDSAKeyPair_OpenSSL>);
  static_assert(!std::is_copy_assignable_v<MLDSAKeyPair_OpenSSL>);
  static_assert(std::has_virtual_destructor_v<MLDSAKeyPair>);
  static_assert(std::has_virtual_destructor_v<MLDSAPublicKey>);

  OpenSSL::Unique_PKEY native_public(std::span<const uint8_t> der)
  {
    const auto* cursor = der.data();
    OpenSSL::Unique_PKEY key(
      d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der.size())),
      EVP_PKEY_free);
    CHECK(cursor == der.data() + der.size());
    return key;
  }

  OpenSSL::Unique_PKEY native_private(std::span<const uint8_t> der)
  {
    const auto* cursor = der.data();
    OpenSSL::Unique_PKEY key(
      d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(der.size())),
      EVP_PKEY_free,
      false);
    OpenSSL::CHECKNULL(static_cast<EVP_PKEY*>(key));
    CHECK(cursor == der.data() + der.size());
    return key;
  }

  OSSL_PARAM context_param(std::span<const uint8_t> ctx_bytes)
  {
    if (ctx_bytes.empty())
    {
      return OSSL_PARAM_construct_end();
    }
    return OSSL_PARAM_construct_octet_string(
      OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
      const_cast<uint8_t*>(ctx_bytes.data()),
      ctx_bytes.size());
  }

  bool native_verify(
    EVP_PKEY* key,
    std::span<const uint8_t> contents,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> ctx_bytes = {})
  {
    OpenSSL::Unique_EVP_MD_CTX ctx;
    OSSL_PARAM params[] = {
      context_param(ctx_bytes), OSSL_PARAM_construct_end()};
    OpenSSL::CHECK1(EVP_DigestVerifyInit_ex(
      ctx, nullptr, nullptr, nullptr, nullptr, key, params));
    return EVP_DigestVerify(
             ctx,
             signature.data(),
             signature.size(),
             contents.data(),
             contents.size()) == 1;
  }

  std::vector<uint8_t> native_sign(
    EVP_PKEY* key,
    std::span<const uint8_t> contents,
    std::span<const uint8_t> ctx_bytes = {})
  {
    OpenSSL::Unique_EVP_MD_CTX ctx;
    OSSL_PARAM params[] = {
      context_param(ctx_bytes), OSSL_PARAM_construct_end()};
    OpenSSL::CHECK1(EVP_DigestSignInit_ex(
      ctx, nullptr, nullptr, nullptr, nullptr, key, params));
    size_t size = 0;
    OpenSSL::CHECK1(
      EVP_DigestSign(ctx, nullptr, &size, contents.data(), contents.size()));
    std::vector<uint8_t> signature(size);
    OpenSSL::CHECK1(EVP_DigestSign(
      ctx, signature.data(), &size, contents.data(), contents.size()));
    signature.resize(size);
    return signature;
  }

  Pem pem_from_der(std::span<const uint8_t> der, const char* label)
  {
    OpenSSL::Unique_BIO bio;
    OpenSSL::CHECKPOSITIVE(
      PEM_write_bio(bio, label, "", der.data(), static_cast<long>(der.size())));
    const auto data = OpenSSL::bio_contents(bio);
    return Pem(data);
  }

  std::vector<uint8_t> asn1_field(
    int tag,
    std::span<const uint8_t> contents,
    int tag_class = V_ASN1_UNIVERSAL,
    bool constructed = false)
  {
    constructed = constructed || tag == V_ASN1_SEQUENCE || tag == V_ASN1_SET;
    const auto size =
      ASN1_object_size(static_cast<int>(constructed), contents.size(), tag);
    OpenSSL::CHECKPOSITIVE(size);
    std::vector<uint8_t> result(static_cast<size_t>(size));
    auto* cursor = result.data();
    ASN1_put_object(
      &cursor, static_cast<int>(constructed), contents.size(), tag, tag_class);
    std::ranges::copy(contents, cursor);
    return result;
  }

  std::vector<uint8_t> public_encoding(
    int algorithm_nid, std::span<const uint8_t> public_key)
  {
    auto* oid = OBJ_nid2obj(algorithm_nid);
    OpenSSL::CHECKNULL(oid);
    const auto size = i2d_ASN1_OBJECT(oid, nullptr);
    OpenSSL::CHECKPOSITIVE(size);
    std::vector<uint8_t> algorithm(size);
    auto* cursor = algorithm.data();
    OpenSSL::CHECKEQUAL(size, i2d_ASN1_OBJECT(oid, &cursor));
    auto fields = asn1_field(V_ASN1_SEQUENCE, algorithm);
    std::vector<uint8_t> bits = {0};
    bits.insert(bits.end(), public_key.begin(), public_key.end());
    const auto bit_string = asn1_field(V_ASN1_BIT_STRING, bits);
    fields.insert(fields.end(), bit_string.begin(), bit_string.end());
    return asn1_field(V_ASN1_SEQUENCE, fields);
  }

  template <typename F>
  void check_rejected_import(F&& import)
  {
    CHECK_THROWS_AS(import(), std::invalid_argument);
  }

  std::vector<uint8_t> private_encoding(
    int algorithm_nid,
    std::span<const uint8_t> inner,
    int version = 0,
    int algorithm_parameters = V_ASN1_UNDEF)
  {
    OpenSSL::Unique_PKCS8_PRIV_KEY_INFO info;
    auto* object = OBJ_nid2obj(algorithm_nid);
    OpenSSL::CHECKNULL(object);
    OpenSSL::Unique_ASN1_OBJECT algorithm(OBJ_dup(object));
    const auto free_bytes = [](unsigned char* bytes) { OPENSSL_free(bytes); };
    std::unique_ptr<unsigned char, decltype(free_bytes)> copy(
      static_cast<unsigned char*>(OPENSSL_memdup(inner.data(), inner.size())),
      free_bytes);
    OpenSSL::CHECKNULL(copy.get());
    OpenSSL::CHECK1(PKCS8_pkey_set0(
      info,
      algorithm,
      version,
      algorithm_parameters,
      nullptr,
      copy.get(),
      inner.size()));
    algorithm.release();
    (void)copy.release();
    const auto size = i2d_PKCS8_PRIV_KEY_INFO(info, nullptr);
    OpenSSL::CHECKPOSITIVE(size);
    std::vector<uint8_t> der(size);
    auto* cursor = der.data();
    OpenSSL::CHECKEQUAL(size, i2d_PKCS8_PRIV_KEY_INFO(info, &cursor));
    return der;
  }

  std::vector<uint8_t> native_bytes(
    EVP_PKEY* key, const char* param, size_t size)
  {
    std::vector<uint8_t> bytes(size);
    size_t written = 0;
    OpenSSL::CHECK1(EVP_PKEY_get_octet_string_param(
      key, param, bytes.data(), bytes.size(), &written));
    REQUIRE(written == size);
    return bytes;
  }
}

TEST_SUITE_BEGIN("ML-DSA");

TEST_CASE("ML-DSA generation, serialization, signing and verification")
{
  for (const auto& info : PARAMETER_SETS)
  {
    SUBCASE(info.name)
    {
      const auto parameters = info.id;
      auto key = make_mldsa_key_pair(parameters);
      CHECK(key->get_parameter_set() == parameters);
      const auto public_der = key->public_key_der();
      auto public_pem = make_mldsa_public_key(key->public_key_pem());
      auto public_key = make_mldsa_public_key(public_der);
      auto private_pem = make_mldsa_key_pair(key->private_key_pem());
      auto private_der = make_mldsa_key_pair(key->private_key_der());
      for (const auto& imported : {private_pem, private_der})
      {
        CHECK(imported->get_parameter_set() == parameters);
        CHECK(imported->public_key_der() == public_der);
        CHECK(imported->public_key_pem() == key->public_key_pem());
      }
      for (const auto& imported : {public_key, public_pem})
      {
        CHECK(imported->get_parameter_set() == parameters);
        CHECK(imported->public_key_der() == public_der);
        CHECK(imported->public_key_pem() == key->public_key_pem());
      }
      for (size_t round = 0; round < 4; ++round)
      {
        const auto signature = key->sign(message, context);
        CHECK(signature.size() == info.signature_size);
        for (const auto& verifier : {key, private_pem, private_der})
        {
          CHECK(verifier->verify(message, signature, context));
          CHECK(public_key->verify(
            message, verifier->sign(message, context), context));
        }
        CHECK(public_key->verify(message, signature, context));
        CHECK(public_pem->verify(message, signature, context));
      }
      auto native_pub = native_public(public_der);
      auto native_priv = native_private(key->private_key_der());
      CHECK(native_verify(
        native_pub, message, key->sign(message, context), context));
      CHECK(public_key->verify(
        message, native_sign(native_priv, message, context), context));
    }
  }
}

TEST_CASE("ML-DSA message and context boundaries")
{
  for (const auto& info : PARAMETER_SETS)
  {
    SUBCASE(info.name)
    {
      const auto parameters = info.id;
      auto key = make_mldsa_key_pair(parameters);
      auto public_key = make_mldsa_public_key(key->public_key_der());
      std::array<uint8_t, MAX_CONTEXT_BYTES> max_context{};
      max_context.front() = 255;
      max_context.back() = 128;
      const std::array<uint8_t, MAX_CONTEXT_BYTES + 1> oversized_context{};
      const std::array<std::vector<uint8_t>, 4> messages = {
        std::vector<uint8_t>{},
        std::vector<uint8_t>{0},
        std::vector<uint8_t>(32, 127),
        std::vector<uint8_t>(size_t{1024} * 1024, 255)};
      for (const auto& contents : messages)
      {
        INFO("Message length: " << contents.size());
        const auto signature = key->sign(contents);
        CHECK(public_key->verify(contents, signature));
        CHECK_FALSE(public_key->verify(contents, signature, context));
        const auto contextual = key->sign(contents, max_context);
        CHECK(public_key->verify(contents, contextual, max_context));
        CHECK_FALSE(public_key->verify(contents, contextual));
      }
      // OpenSSL rejects contexts above 255 bytes when the parameter is set.
      const auto plain_signature = key->sign(message);
      CHECK_THROWS((void)key->sign(message, oversized_context));
      CHECK_THROWS(
        (void)public_key->verify(message, plain_signature, oversized_context));
      CHECK_THROWS(
        (void)key->verify(message, plain_signature, oversized_context));
      // A rejected context throws even when the signature size is invalid.
      CHECK_THROWS((void)public_key->verify(message, {}, oversized_context));
      CHECK_THROWS((void)key->verify(message, {}, oversized_context));
      CHECK(public_key->verify(message, key->sign(message)));
    }
  }
}

TEST_CASE("ML-DSA rejects corrupted signatures, messages and wrong keys")
{
  for (const auto& info : PARAMETER_SETS)
  {
    SUBCASE(info.name)
    {
      auto key = make_mldsa_key_pair(info.id);
      auto verifier = make_mldsa_public_key(key->public_key_der());
      const auto signature = key->sign(message, context);
      auto corrupt_message = message;
      corrupt_message[0] ^= 1;
      auto wrong_context = context;
      wrong_context[0] ^= 1;
      CHECK_FALSE(verifier->verify(corrupt_message, signature, context));
      CHECK_FALSE(verifier->verify(message, signature, wrong_context));
      CHECK_FALSE(verifier->verify(message, signature));
      CHECK_FALSE(verifier->verify(message, {}, context));
      for (const size_t position :
           {size_t(0), signature.size() / 2, signature.size() - 1})
      {
        auto corrupted = signature;
        corrupted[position] ^= 1;
        CHECK_FALSE(verifier->verify(message, corrupted, context));
      }
      auto shorter = signature;
      shorter.pop_back();
      CHECK_FALSE(verifier->verify(message, shorter, context));
      auto longer = signature;
      longer.push_back(0);
      CHECK_FALSE(verifier->verify(message, longer, context));
      auto wrong_key = make_mldsa_key_pair(info.id);
      CHECK_FALSE(wrong_key->verify(message, signature, context));
      for (const auto& other : PARAMETER_SETS)
      {
        if (other.id != info.id)
        {
          auto wrong_parameters = make_mldsa_key_pair(other.id);
          CHECK_FALSE(wrong_parameters->verify(message, signature, context));
        }
      }
      CHECK(verifier->verify(message, signature, context));
    }
  }
}

TEST_CASE("ML-DSA imports reject malformed encodings")
{
  CHECK_THROWS_AS(
    make_mldsa_key_pair(static_cast<MLDSAParameterSet>(255)),
    std::invalid_argument);
  CHECK_THROWS(make_mldsa_key_pair(Pem{}));
  CHECK_THROWS(make_mldsa_public_key(Pem{}));
  CHECK_THROWS(make_mldsa_key_pair(std::span<const uint8_t>{}));
  CHECK_THROWS(make_mldsa_public_key(std::span<const uint8_t>{}));
  for (const auto& info : PARAMETER_SETS)
  {
    SUBCASE(info.name)
    {
      const auto parameters = info.id;
      auto key = make_mldsa_key_pair(parameters);
      const auto private_der = key->private_key_der();
      const auto public_der = key->public_key_der();
      const auto private_pem = key->private_key_pem();
      const auto public_pem = key->public_key_pem();
      CHECK_THROWS(make_mldsa_key_pair(public_der));
      CHECK_THROWS(make_mldsa_key_pair(public_pem));
      CHECK_THROWS(make_mldsa_public_key(private_der));
      CHECK_THROWS(make_mldsa_public_key(private_pem));
      for (const bool is_private : {false, true})
      {
        const auto& der = is_private ? private_der : public_der;
        const auto& pem = is_private ? private_pem : public_pem;
        const auto load_der = [&](std::span<const uint8_t> encoded) {
          if (is_private)
          {
            make_mldsa_key_pair(encoded);
          }
          else
          {
            make_mldsa_public_key(encoded);
          }
        };
        const auto load_pem = [&](const Pem& encoded) {
          if (is_private)
          {
            make_mldsa_key_pair(encoded);
          }
          else
          {
            make_mldsa_public_key(encoded);
          }
        };
        CHECK_THROWS_AS(
          load_der(std::span(der).first(der.size() - 1)),
          std::invalid_argument);
        auto trailing = der;
        trailing.push_back(0);
        CHECK_THROWS_AS(load_der(trailing), std::invalid_argument);
        auto bad_base64 = pem.str();
        bad_base64[bad_base64.find('\n') + 1] = '!';
        CHECK_THROWS_AS(load_pem(Pem(bad_base64)), std::invalid_argument);
      }
    }
  }
}

TEST_CASE("ML-DSA expanded private keys and corrupted key material")
{
  // FIPS 204 skEncode fields start with rho (32), K (32), then tr (64).
  constexpr size_t RHO_OFFSET = 0;
  constexpr size_t PUBLIC_KEY_HASH_OFFSET = 64;
  constexpr size_t SECRET_POLYNOMIAL_OFFSET = 128;
  for (const auto& info : PARAMETER_SETS)
  {
    SUBCASE(info.name)
    {
      OpenSSL::Unique_PKEY native(
        EVP_PKEY_Q_keygen(nullptr, nullptr, info.name), EVP_PKEY_free);
      const auto expanded =
        native_bytes(native, OSSL_PKEY_PARAM_PRIV_KEY, info.expanded_key_size);
      const auto encoded =
        private_encoding(info.nid, asn1_field(V_ASN1_OCTET_STRING, expanded));
      const auto native_signature = native_sign(native, message, context);
      auto imported = make_mldsa_key_pair(encoded);
      CHECK(imported->get_parameter_set() == info.id);
      CHECK(imported->verify(message, native_signature, context));
      CHECK(native_verify(
        native, message, imported->sign(message, context), context));
      auto pem_key = make_mldsa_key_pair(pem_from_der(encoded, "PRIVATE KEY"));
      CHECK(pem_key->public_key_der() == imported->public_key_der());

      for (const size_t position :
           {RHO_OFFSET,
            PUBLIC_KEY_HASH_OFFSET,
            SECRET_POLYNOMIAL_OFFSET,
            size_t{200},
            info.s2_offset,
            expanded.size() - 1})
      {
        auto corrupted = expanded;
        corrupted[position] ^= 1;
        CHECK_THROWS_WITH_AS(
          make_mldsa_key_pair(private_encoding(
            info.nid, asn1_field(V_ASN1_OCTET_STRING, corrupted))),
          "ML-DSA provider rejected the key material",
          std::invalid_argument);
      }
      for (const size_t length :
           {size_t(0), expanded.size() - 1, expanded.size() + 1})
      {
        const std::vector<uint8_t> corrupted(length, 0);
        CHECK_THROWS(make_mldsa_key_pair(private_encoding(
          info.nid, asn1_field(V_ASN1_OCTET_STRING, corrupted))));
      }
    }
  }
}

TEST_CASE("ML-DSA rejects other key families")
{
  auto ec = make_ec_key_pair();
  auto rsa = make_rsa_key_pair();
  auto eddsa = make_eddsa_key_pair();
  for (const auto& pem :
       {ec->private_key_pem(),
        rsa->private_key_pem(),
        eddsa->private_key_pem()})
  {
    CHECK_THROWS_AS(make_mldsa_key_pair(pem), std::invalid_argument);
  }
  for (const auto& pem :
       {ec->public_key_pem(), rsa->public_key_pem(), eddsa->public_key_pem()})
  {
    CHECK_THROWS_AS(make_mldsa_public_key(pem), std::invalid_argument);
  }
  CHECK_THROWS_AS(
    make_mldsa_public_key(ec->public_key_der()), std::invalid_argument);
  CHECK_THROWS_AS(
    make_mldsa_key_pair(ec->private_key_der()), std::invalid_argument);
}

TEST_CASE("ML-DSA key lifetime and concurrent operations")
{
  for (const auto& info : PARAMETER_SETS)
  {
    SUBCASE(info.name)
    {
      const auto parameters = info.id;
      MLDSAPublicKeyPtr public_key;
      std::vector<uint8_t> signature;
      {
        auto key = make_mldsa_key_pair(parameters);
        public_key = make_mldsa_public_key(key->public_key_der());
        signature = key->sign(message);
        std::vector<std::future<bool>> results;
        results.reserve(4);
        for (size_t worker = 0; worker < 4; ++worker)
        {
          results.push_back(std::async(std::launch::async, [key, public_key] {
            for (size_t round = 0; round < 8; ++round)
            {
              if (!public_key->verify(
                    message, key->sign(message, context), context))
              {
                return false;
              }
            }
            return true;
          }));
        }
        for (auto& result : results)
        {
          CHECK(result.get());
        }
      }
      CHECK(public_key->verify(message, signature));
      for (size_t round = 0; round < 12; ++round)
      {
        auto key = make_mldsa_key_pair(parameters);
        auto imported = make_mldsa_key_pair(key->private_key_der());
        auto der = key->public_key_der();
        der.push_back(0);
        CHECK_THROWS(make_mldsa_public_key(der));
        CHECK(imported->verify(message, key->sign(message)));
      }
    }
  }
}

TEST_CASE("ML-DSA parameter-set pinning at admission")
{
  for (const auto& info : PARAMETER_SETS)
  {
    SUBCASE(info.name)
    {
      const auto parameters = info.id;
      auto key = make_mldsa_key_pair(parameters);
      const auto private_pem = key->private_key_pem();
      const auto private_der = key->private_key_der();
      const auto public_pem = key->public_key_pem();
      const auto public_der = key->public_key_der();
      CHECK(
        make_mldsa_key_pair(private_pem, parameters)->get_parameter_set() ==
        parameters);
      CHECK(
        make_mldsa_key_pair(private_der, parameters)->get_parameter_set() ==
        parameters);
      CHECK(
        make_mldsa_public_key(public_pem, parameters)->get_parameter_set() ==
        parameters);
      CHECK(
        make_mldsa_public_key(public_der, parameters)->get_parameter_set() ==
        parameters);
      for (const auto& other : PARAMETER_SETS)
      {
        const auto expected = other.id;
        if (expected == parameters)
        {
          continue;
        }
        check_rejected_import(
          [&] { make_mldsa_key_pair(private_pem, expected); });
        check_rejected_import(
          [&] { make_mldsa_key_pair(private_der, expected); });
        check_rejected_import(
          [&] { make_mldsa_public_key(public_pem, expected); });
        check_rejected_import(
          [&] { make_mldsa_public_key(public_der, expected); });
      }
    }
  }
}

TEST_CASE("ML-DSA NIST ACVP pure sigVer known answers")
{
  for (const auto& vector : mldsa_test_vectors::ACVP_SIG_VER)
  {
    const auto pk = ccf::ds::from_hex(std::string(vector.public_key));
    const auto contents = ccf::ds::from_hex(std::string(vector.message));
    const auto signature = ccf::ds::from_hex(std::string(vector.signature));
    const auto ctx = ccf::ds::from_hex(std::string(vector.context));
    REQUIRE_FALSE(ctx.empty());
    auto key = make_mldsa_public_key(
      public_encoding(info_for(vector.parameters).nid, pk), vector.parameters);
    CHECK(key->verify(contents, signature, ctx) == vector.test_passed);
    CHECK_FALSE(key->verify(contents, signature));
  }
}

TEST_SUITE_END;
