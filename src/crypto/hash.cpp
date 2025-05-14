// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/hash.h"

#include "ccf/crypto/hkdf.h"
#include "ccf/crypto/sha256.h"

namespace ccf::crypto
{
  void default_sha256(const std::span<const uint8_t>& data, uint8_t* h)
  {
    openssl_sha256(data, h);
  }

  std::vector<uint8_t> sha256(const std::vector<uint8_t>& data)
  {
    size_t hash_size = EVP_MD_size(OpenSSL::get_md_type(MDType::SHA256));
    std::vector<uint8_t> r(hash_size);
    openssl_sha256(data, r.data());
    return r;
  }

  std::vector<uint8_t> sha256(const std::span<uint8_t const>& data)
  {
    size_t hash_size = EVP_MD_size(OpenSSL::get_md_type(MDType::SHA256));
    std::vector<uint8_t> r(hash_size);
    openssl_sha256(data, r.data());
    return r;
  }

  std::vector<uint8_t> sha256(const uint8_t* data, size_t len)
  {
    std::span<const uint8_t> buf(data, len);
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
    const std::span<const uint8_t>& ikm,
    const std::span<const uint8_t>& salt,
    const std::span<const uint8_t>& info)
  {
    return OpenSSL::hkdf(md_type, length, ikm, salt, info);
  }
}