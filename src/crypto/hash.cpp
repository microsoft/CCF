// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <mbedtls/sha256.h>

#ifdef HAVE_OPENSSL
#  include <openssl/sha.h>
#endif

#include "../tls/mbedtls_wrappers.h"
#include "hash.h"

#include <stdexcept>
using namespace std;

namespace crypto
{
  void Sha256Hash::mbedtls_sha256(const CBuffer& data, uint8_t* h)
  {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);

    mbedtls_sha256_update_ret(&ctx, data.p, data.rawSize());

    mbedtls_sha256_finish_ret(&ctx, h);
    mbedtls_sha256_free(&ctx);
  }

#ifdef HAVE_OPENSSL
  void Sha256Hash::openssl_sha256(const CBuffer& data, uint8_t* h)
  {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.p, data.rawSize());
    SHA256_Final(h, &ctx);
  }
#endif

  Sha256Hash::Sha256Hash() : h{0} {}
  Sha256Hash::Sha256Hash(const CBuffer& data) : h{0}
  {
    mbedtls_sha256(data, h.data());
  }

  ISha256MbedTLS::ISha256MbedTLS()
  {
    ctx = new mbedtls_sha256_context();
    mbedtls_sha256_starts_ret((mbedtls_sha256_context*)ctx, 0);
  }

  ISha256MbedTLS::~ISha256MbedTLS()
  {
    delete (mbedtls_sha256_context*)ctx;
  }

  Sha256Hash ISha256MbedTLS::finalise()
  {
    if (!ctx)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    Sha256Hash r;
    mbedtls_sha256_finish_ret((mbedtls_sha256_context*)ctx, r.h.data());
    mbedtls_sha256_free((mbedtls_sha256_context*)ctx);
    delete (mbedtls_sha256_context*)ctx;
    ctx = nullptr;
    return r;
  }

  void ISha256MbedTLS::update_hash(CBuffer data)
  {
    if (!ctx)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    mbedtls_sha256_update_ret(
      (mbedtls_sha256_context*)ctx, data.p, data.rawSize());
  }

#ifdef HAVE_OPENSSL
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
#endif
}