// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/hash.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>

namespace crypto
{
  namespace OpenSSL
  {
    std::vector<uint8_t> hkdf(
      MDType md_type,
      size_t length,
      const std::vector<uint8_t>& ikm,
      const std::vector<uint8_t>& salt,
      const std::vector<uint8_t>& info)
    {
      auto md = get_md_type(md_type);
      EVP_PKEY_CTX* pctx;
      std::vector<uint8_t> r(length);
      pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      CHECK1(EVP_PKEY_derive_init(pctx));
      CHECK1(EVP_PKEY_CTX_set_hkdf_md(pctx, md));
      CHECK1(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()));
      CHECK1(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()));
      CHECK1(EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()));
      size_t outlen = length;
      CHECK1(EVP_PKEY_derive(pctx, r.data(), &outlen));
      EVP_PKEY_CTX_free(pctx);
      r.resize(outlen);
      return r;
    }
  }

  using namespace OpenSSL;

  void openssl_sha256(const std::span<const uint8_t>& data, uint8_t* h)
  {
    const EVP_MD* md = EVP_sha256();
    int rc = EVP_Digest(data.data(), data.size(), h, nullptr, md, nullptr);
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_Digest failed: {}", rc));
    }
  }

  ISha256OpenSSL::ISha256OpenSSL()
  {
    const EVP_MD* md = EVP_sha256();
    ctx = EVP_MD_CTX_new();
    int rc = EVP_DigestInit(ctx, md);
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_DigestInit failed: {}", rc));
    }
  }

  ISha256OpenSSL::~ISha256OpenSSL()
  {
    if (ctx)
    {
      EVP_MD_CTX_free(ctx);
    }
  }

  void ISha256OpenSSL::update_hash(std::span<const uint8_t> data)
  {
    if (!ctx)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    int rc = EVP_DigestUpdate(ctx, data.data(), data.size());
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_DigestUpdate failed: {}", rc));
    }
  }

  Sha256Hash ISha256OpenSSL::finalise()
  {
    if (!ctx)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    Sha256Hash r;
    int rc = EVP_DigestFinal(ctx, r.h.data(), nullptr);
    if (rc != 1)
    {
      EVP_MD_CTX_free(ctx);
      throw std::logic_error(fmt::format("EVP_DigestFinal failed: {}", rc));
    }
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
    return r;
  }
}