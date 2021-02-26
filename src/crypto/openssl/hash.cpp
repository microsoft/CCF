// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "hash.h"

#include <openssl/sha.h>
#include <stdexcept>

namespace crypto
{
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