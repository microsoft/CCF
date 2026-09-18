// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "crypto/openssl/mldsa.h"
#  include "crypto/openssl/mldsa_public_key.h"
#  include "ds/internal_logger.h"

#  include <openssl/pem.h>
#  include <openssl/x509.h>
#  include <stdexcept>

namespace ccf::crypto
{
  MLDSAPublicKey_OpenSSL::MLDSAPublicKey_OpenSSL(
    const Pem& pem, std::optional<MLDSAParameterSet> expected)
  {
    OpenSSL::Unique_BIO mem(pem);
    auto* decoded = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
    if (decoded == nullptr)
    {
      throw std::invalid_argument("Malformed ML-DSA public key PEM");
    }
    key.reset(decoded);
    mldsa::parameter_set(key, expected);
    OpenSSL::check_key(key, false);
  }

  MLDSAPublicKey_OpenSSL::MLDSAPublicKey_OpenSSL(
    std::span<const uint8_t> der, std::optional<MLDSAParameterSet> expected)
  {
    const auto* cursor = der.data();
    auto* decoded = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der.size()));
    if (decoded == nullptr)
    {
      throw std::invalid_argument("Malformed ML-DSA public key DER");
    }
    key.reset(decoded);
    if (cursor != der.data() + der.size())
    {
      throw std::invalid_argument("Unexpected data after ML-DSA public key");
    }
    mldsa::parameter_set(key, expected);
    OpenSSL::check_key(key, false);
  }

  MLDSAParameterSet MLDSAPublicKey_OpenSSL::get_parameter_set() const
  {
    return mldsa::parameter_set(key);
  }

  Pem MLDSAPublicKey_OpenSSL::public_key_pem() const
  {
    OpenSSL::Unique_BIO bio;
    OpenSSL::CHECK1(PEM_write_bio_PUBKEY(bio, key));
    const auto data = OpenSSL::bio_contents(bio);
    return {data.data(), data.size()};
  }

  std::vector<uint8_t> MLDSAPublicKey_OpenSSL::public_key_der() const
  {
    OpenSSL::Unique_BIO bio;
    OpenSSL::CHECK1(i2d_PUBKEY_bio(bio, key));
    const auto data = OpenSSL::bio_contents(bio);
    return {data.begin(), data.end()};
  }

  bool MLDSAPublicKey_OpenSSL::verify(
    std::span<const uint8_t> contents,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> context)
  {
    const auto signature_size = EVP_PKEY_get_size(key);
    OpenSSL::CHECKPOSITIVE(signature_size);
    if (signature.size() != static_cast<size_t>(signature_size))
    {
      LOG_TRACE_FMT("ML-DSA signature has an invalid size");
      return false;
    }

    OpenSSL::Unique_EVP_MD_CTX ctx;
    EVP_PKEY_CTX* pctx = nullptr;
    OpenSSL::CHECK1(EVP_DigestVerifyInit_ex(
      ctx, &pctx, nullptr, nullptr, nullptr, key, nullptr));
    if (!context.empty())
    {
      mldsa::set_context(pctx, context);
    }

    const auto rc = EVP_DigestVerify(
      ctx,
      signature.data(),
      signature.size(),
      contents.data(),
      contents.size());
    if (rc == 1)
    {
      return true;
    }
    if (rc == 0)
    {
      LOG_TRACE_FMT("ML-DSA signature verification failed");
      return false;
    }
    throw std::runtime_error(
      fmt::format("ML-DSA provider failed verification (rc={})", rc));
  }

  MLDSAPublicKeyPtr make_mldsa_public_key(const Pem& pem)
  {
    return std::make_shared<MLDSAPublicKey_OpenSSL>(pem);
  }

  MLDSAPublicKeyPtr make_mldsa_public_key(std::span<const uint8_t> der)
  {
    return std::make_shared<MLDSAPublicKey_OpenSSL>(der);
  }

  MLDSAPublicKeyPtr make_mldsa_public_key(
    const Pem& pem, MLDSAParameterSet expected)
  {
    return std::make_shared<MLDSAPublicKey_OpenSSL>(pem, expected);
  }

  MLDSAPublicKeyPtr make_mldsa_public_key(
    std::span<const uint8_t> der, MLDSAParameterSet expected)
  {
    return std::make_shared<MLDSAPublicKey_OpenSSL>(der, expected);
  }
}
#endif // OPENSSL_VERSION_PREREQ
