// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "crypto/openssl/mldsa.h"
#  include "crypto/openssl/mldsa_key_pair.h"

#  include <openssl/pem.h>
#  include <openssl/x509.h>
#  include <stdexcept>

namespace ccf::crypto
{
  MLDSAKeyPair_OpenSSL::MLDSAKeyPair_OpenSSL(MLDSAParameterSet parameter_set)
  {
    OpenSSL::Unique_EVP_PKEY_CTX ctx(mldsa::openssl_name(parameter_set));
    OpenSSL::CHECK1(EVP_PKEY_keygen_init(ctx));
    EVP_PKEY* generated = nullptr;
    OpenSSL::CHECK1(EVP_PKEY_generate(ctx, &generated));
    OpenSSL::CHECKNULL(generated);
    key.reset(generated);
    OpenSSL::check_key(key, true);
  }

  MLDSAKeyPair_OpenSSL::MLDSAKeyPair_OpenSSL(
    const Pem& pem, std::optional<MLDSAParameterSet> expected)
  {
    OpenSSL::Unique_BIO mem(pem);
    auto* decoded = PEM_read_bio_PrivateKey(mem, nullptr, nullptr, nullptr);
    if (decoded == nullptr)
    {
      throw std::invalid_argument("Malformed ML-DSA private key PEM");
    }
    key.reset(decoded);
    mldsa::parameter_set(key, expected);
    OpenSSL::check_key(key, true);
  }

  MLDSAKeyPair_OpenSSL::MLDSAKeyPair_OpenSSL(
    std::span<const uint8_t> der, std::optional<MLDSAParameterSet> expected)
  {
    const auto* cursor = der.data();
    // The PKCS#8 structure decoder selects the key type from the
    // AlgorithmIdentifier, which keeps OpenSSL's legacy format probing out
    // of the path.
    auto* decoded =
      d2i_PKCS8_PRIV_KEY_INFO(nullptr, &cursor, static_cast<long>(der.size()));
    if (decoded == nullptr)
    {
      throw std::invalid_argument("Malformed ML-DSA private key DER");
    }
    const OpenSSL::Unique_PKCS8_PRIV_KEY_INFO info(decoded);
    if (cursor != der.data() + der.size())
    {
      throw std::invalid_argument("Unexpected data after ML-DSA private key");
    }
    auto* converted = EVP_PKCS82PKEY(info);
    if (converted == nullptr)
    {
      throw std::invalid_argument("ML-DSA provider rejected the key material");
    }
    key.reset(converted);
    mldsa::parameter_set(key, expected);
    OpenSSL::check_key(key, true);
  }

  MLDSAParameterSet MLDSAKeyPair_OpenSSL::get_parameter_set() const
  {
    return MLDSAPublicKey_OpenSSL::get_parameter_set();
  }

  Pem MLDSAKeyPair_OpenSSL::private_key_pem() const
  {
    // BIO_s_mem clears its buffer on growth and release.
    OpenSSL::Unique_BIO bio;
    OpenSSL::CHECK1(PEM_write_bio_PrivateKey(
      bio, key, nullptr, nullptr, 0, nullptr, nullptr));
    const auto data = OpenSSL::bio_contents(bio);
    return {data.data(), data.size()};
  }

  std::vector<uint8_t> MLDSAKeyPair_OpenSSL::private_key_der() const
  {
    OpenSSL::Unique_BIO bio;
    // i2d_PrivateKey_bio prefers a type-specific structure and only falls
    // back to PKCS#8, so request the PrivateKeyInfo encoder explicitly.
    OpenSSL::CHECK1(
      i2d_PKCS8PrivateKey_bio(bio, key, nullptr, nullptr, 0, nullptr, nullptr));
    const auto data = OpenSSL::bio_contents(bio);
    return {data.begin(), data.end()};
  }

  Pem MLDSAKeyPair_OpenSSL::public_key_pem() const
  {
    return MLDSAPublicKey_OpenSSL::public_key_pem();
  }

  std::vector<uint8_t> MLDSAKeyPair_OpenSSL::public_key_der() const
  {
    return MLDSAPublicKey_OpenSSL::public_key_der();
  }

  std::vector<uint8_t> MLDSAKeyPair_OpenSSL::sign(
    std::span<const uint8_t> contents, std::span<const uint8_t> context) const
  {
    OpenSSL::Unique_EVP_MD_CTX ctx;
    EVP_PKEY_CTX* pctx = nullptr;
    OpenSSL::CHECK1(EVP_DigestSignInit_ex(
      ctx, &pctx, nullptr, nullptr, nullptr, key, nullptr));
    if (!context.empty())
    {
      mldsa::set_context(pctx, context);
    }

    const auto signature_size = EVP_PKEY_get_size(key);
    OpenSSL::CHECKPOSITIVE(signature_size);
    std::vector<uint8_t> signature(static_cast<size_t>(signature_size));
    auto written = signature.size();
    OpenSSL::CHECK1(EVP_DigestSign(
      ctx, signature.data(), &written, contents.data(), contents.size()));
    if (written != signature.size())
    {
      throw std::runtime_error(
        "ML-DSA provider returned an unexpected signature size");
    }
    return signature;
  }

  bool MLDSAKeyPair_OpenSSL::verify(
    std::span<const uint8_t> contents,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> context)
  {
    return MLDSAPublicKey_OpenSSL::verify(contents, signature, context);
  }

  MLDSAKeyPairPtr make_mldsa_key_pair(MLDSAParameterSet parameter_set)
  {
    return std::make_shared<MLDSAKeyPair_OpenSSL>(parameter_set);
  }

  MLDSAKeyPairPtr make_mldsa_key_pair(const Pem& pem)
  {
    return std::make_shared<MLDSAKeyPair_OpenSSL>(pem);
  }

  MLDSAKeyPairPtr make_mldsa_key_pair(std::span<const uint8_t> der)
  {
    return std::make_shared<MLDSAKeyPair_OpenSSL>(der);
  }

  MLDSAKeyPairPtr make_mldsa_key_pair(
    const Pem& pem, MLDSAParameterSet expected)
  {
    return std::make_shared<MLDSAKeyPair_OpenSSL>(pem, expected);
  }

  MLDSAKeyPairPtr make_mldsa_key_pair(
    std::span<const uint8_t> der, MLDSAParameterSet expected)
  {
    return std::make_shared<MLDSAKeyPair_OpenSSL>(der, expected);
  }
}
#endif // OPENSSL_VERSION_PREREQ
