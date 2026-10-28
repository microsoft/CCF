// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/mldsa_public_key.h"

#include "crypto/openssl/mldsa.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "crypto/openssl/mldsa_public_key.h"
#  include "ds/internal_logger.h"

#  include <openssl/core_names.h>
#  include <openssl/params.h>
#  include <openssl/pem.h>
#  include <openssl/x509.h>
#  include <stdexcept>
#  include <tuple>

namespace ccf::crypto
{
  MLDSAPublicKey_OpenSSL::MLDSAPublicKey_OpenSSL(EVP_PKEY* pk)
  {
    key.reset(pk);
    std::ignore = mldsa::parameter_set(key);
    OpenSSL::check_key(key, false);
  }

  std::shared_ptr<MLDSAPublicKey_OpenSSL> MLDSAPublicKey_OpenSSL::from_raw(
    std::span<const uint8_t> raw_public_key, MLDSAParameterSet parameter_set)
  {
    OpenSSL::Unique_EVP_PKEY_CTX ctx(mldsa::openssl_name(parameter_set));
    OpenSSL::CHECK1(EVP_PKEY_fromdata_init(ctx));
    OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY,
        const_cast<uint8_t*>(raw_public_key.data()),
        raw_public_key.size()),
      OSSL_PARAM_construct_end()};
    EVP_PKEY* imported = nullptr;
    // The provider rejects public keys of the wrong size.
    if (
      EVP_PKEY_fromdata(ctx, &imported, EVP_PKEY_PUBLIC_KEY, params) != 1 ||
      imported == nullptr)
    {
      throw std::invalid_argument(
        fmt::format("Malformed ML-DSA public key: {}", OpenSSL::first_error()));
    }
    return std::make_shared<MLDSAPublicKey_OpenSSL>(imported);
  }

  MLDSAPublicKey_OpenSSL::MLDSAPublicKey_OpenSSL(
    const Pem& pem, std::optional<MLDSAParameterSet> expected)
  {
    OpenSSL::Unique_BIO mem(pem);
    auto* decoded = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
    if (decoded == nullptr)
    {
      throw std::invalid_argument(fmt::format(
        "Malformed ML-DSA public key PEM: {}", OpenSSL::first_error()));
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
      throw std::invalid_argument(fmt::format(
        "Malformed ML-DSA public key DER: {}", OpenSSL::first_error()));
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

  std::vector<uint8_t> MLDSAPublicKey_OpenSSL::public_key_raw() const
  {
    size_t size = 0;
    OpenSSL::CHECK1(EVP_PKEY_get_octet_string_param(
      key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &size));
    std::vector<uint8_t> raw(size);
    OpenSSL::CHECK1(EVP_PKEY_get_octet_string_param(
      key, OSSL_PKEY_PARAM_PUB_KEY, raw.data(), raw.size(), &size));
    raw.resize(size);
    return raw;
  }

  bool MLDSAPublicKey_OpenSSL::verify(
    std::span<const uint8_t> contents,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> context)
  {
    OpenSSL::Unique_EVP_MD_CTX ctx;
    EVP_PKEY_CTX* pctx = nullptr;
    OpenSSL::CHECK1(EVP_DigestVerifyInit_ex(
      ctx, &pctx, nullptr, nullptr, nullptr, key, nullptr));
    if (!context.empty())
    {
      mldsa::set_context(pctx, context);
    }

    // The context is bound first so that a rejected context throws
    // regardless of the signature, as documented by the interface.
    const auto signature_size = EVP_PKEY_get_size(key);
    OpenSSL::CHECKPOSITIVE(signature_size);
    if (signature.size() != static_cast<size_t>(signature_size))
    {
      LOG_TRACE_FMT("ML-DSA signature has an invalid size");
      return false;
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
      const auto error = OpenSSL::first_error();
      LOG_TRACE_FMT("ML-DSA signature verification failed: {}", error);
      return false;
    }
    throw std::runtime_error(fmt::format(
      "ML-DSA provider failed verification (rc={}): {}",
      rc,
      OpenSSL::first_error()));
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

  MLDSAPublicKeyPtr make_mldsa_public_key_from_raw(
    std::span<const uint8_t> raw_public_key, MLDSAParameterSet parameter_set)
  {
    return MLDSAPublicKey_OpenSSL::from_raw(raw_public_key, parameter_set);
  }
}
#else // Remove this fallback after dropping AL3 support.

namespace ccf::crypto
{
  MLDSAPublicKeyPtr make_mldsa_public_key(const Pem& /*pem*/)
  {
    mldsa::unsupported();
  }

  MLDSAPublicKeyPtr make_mldsa_public_key(std::span<const uint8_t> /*der*/)
  {
    mldsa::unsupported();
  }

  MLDSAPublicKeyPtr make_mldsa_public_key(
    const Pem& /*pem*/, MLDSAParameterSet /*expected*/)
  {
    mldsa::unsupported();
  }

  MLDSAPublicKeyPtr make_mldsa_public_key(
    std::span<const uint8_t> /*der*/, MLDSAParameterSet /*expected*/)
  {
    mldsa::unsupported();
  }

  MLDSAPublicKeyPtr make_mldsa_public_key_from_raw(
    std::span<const uint8_t> /*raw_public_key*/,
    MLDSAParameterSet /*parameter_set*/)
  {
    mldsa::unsupported();
  }
}
#endif // OPENSSL_VERSION_PREREQ
