// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "hash.h"

#include "ds/buffer.h"
#include "mbedtls_wrappers.h"

#include <mbedtls/sha256.h>
#include <stdexcept>

namespace crypto
{
  using namespace mbedtls;

  void mbedtls_sha256(const CBuffer& data, uint8_t* h)
  {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);

    mbedtls_sha256_update_ret(&ctx, data.p, data.rawSize());

    mbedtls_sha256_finish_ret(&ctx, h);
    mbedtls_sha256_free(&ctx);
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
}
