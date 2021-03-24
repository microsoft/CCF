// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "hash.h"

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

  void openssl_sha256(const CBuffer& data, uint8_t* h)
  {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.p, data.rawSize());
    SHA256_Final(h, &ctx);
  }

  ISha256OpenSSL::ISha256OpenSSL()
  {
    ctx = new SHA256_CTX;
    SHA256_Init((SHA256_CTX*)ctx);
  }

  ISha256OpenSSL::~ISha256OpenSSL()
  {
    delete (SHA256_CTX*)ctx;
  }

  void ISha256OpenSSL::update_hash(CBuffer data)
  {
    if (!ctx)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    SHA256_Update((SHA256_CTX*)ctx, data.p, data.rawSize());
  }

  Sha256Hash ISha256OpenSSL::finalise()
  {
    if (!ctx)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    Sha256Hash r;
    SHA256_Final(r.h.data(), (SHA256_CTX*)ctx);
    delete (SHA256_CTX*)ctx;
    ctx = nullptr;
    return r;
  }
}