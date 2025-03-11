// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_provider.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <span>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::crypto
{
  namespace OpenSSL
  {
    inline const EVP_MD* get_md_type(MDType type)
    {
      switch (type)
      {
        case MDType::NONE:
          return nullptr;
        case MDType::SHA1:
          return EVP_sha1();
        case MDType::SHA256:
          return EVP_sha256();
        case MDType::SHA384:
          return EVP_sha384();
        case MDType::SHA512:
          return EVP_sha512();
        default:
          throw std::runtime_error("Unsupported hash algorithm");
      }
      return nullptr;
    }

    std::vector<uint8_t> hkdf(
      MDType md_type,
      size_t length,
      const std::span<const uint8_t>& ikm,
      const std::span<const uint8_t>& salt = {},
      const std::span<const uint8_t>& info = {});
  }

  // Hash Provider (OpenSSL)
  class OpenSSLHashProvider : public HashProvider
  {
  public:
    /** Generic Hash function
     * @param data The data to hash
     * @param size The size of @p data
     * @param type The type of hash to compute
     */
    virtual HashBytes Hash(const uint8_t* data, size_t size, MDType type) const
    {
      auto o_md_type = OpenSSL::get_md_type(type);
      HashBytes r(EVP_MD_size(o_md_type));
      unsigned int len = 0;

      if (EVP_Digest(data, size, r.data(), &len, o_md_type, NULL) != 1)
        throw std::runtime_error("OpenSSL hash update error");

      return r;
    }
  };

  class ISha256OpenSSL : public ISha256Hash
  {
  public:
    ISha256OpenSSL();
    ~ISha256OpenSSL();
    virtual void update_hash(std::span<const uint8_t> data);
    virtual Sha256Hash finalise();

  protected:
    EVP_MD_CTX* ctx = nullptr;
  };

  void openssl_sha256(const std::span<const uint8_t>& data, uint8_t* h);
  void openssl_sha256_init();
  void openssl_sha256_shutdown();
}
