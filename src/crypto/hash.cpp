// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "hash.h"

#include "mbedtls/hash.h"
#include "openssl/hash.h"

#include <openssl/sha.h>

namespace crypto
{
  void default_sha256(const CBuffer& data, uint8_t* h)
  {
    return openssl_sha256(data, h);
  }

  std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data)
  {
    size_t hash_size = EVP_MD_size(OpenSSL::get_md_type(MDType::SHA256));
    std::vector<uint8_t> r(hash_size);
    openssl_sha256(data, r.data());
    return r;
  }

  std::vector<uint8_t> SHA256(const uint8_t* data, size_t len)
  {
    CBuffer buf(data, len);
    size_t hash_size = EVP_MD_size(OpenSSL::get_md_type(MDType::SHA256));
    std::vector<uint8_t> r(hash_size);
    openssl_sha256(buf, r.data());
    return r;
  }

  std::shared_ptr<HashProvider> make_hash_provider()
  {
    return std::make_shared<OpenSSLHashProvider>();
  }

  std::shared_ptr<ISha256Hash> make_incremental_sha256()
  {
    return std::make_shared<ISha256OpenSSL>();
  }

  std::vector<uint8_t> hkdf(
    MDType md_type,
    size_t length,
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info)
  {
#if defined(CRYPTO_PROVIDER_IS_MBEDTLS)
    return mbedtls::hkdf(md_type, length, ikm, salt, info);
#else
    return OpenSSL::hkdf(md_type, length, ikm, salt, info);
#endif
  }
}