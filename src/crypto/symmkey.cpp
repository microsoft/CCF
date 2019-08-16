// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "symmkey.h"

#include "ds/logger.h"
#include "error.h"
#include "tls/error_string.h"

#include <mbedtls/aes.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>

namespace crypto
{
  KeyAesGcm::KeyAesGcm(CBuffer rawKey)
  {
    ctx = new mbedtls_gcm_context;
    mbedtls_gcm_init(reinterpret_cast<mbedtls_gcm_context*>(ctx));

    size_t n_bits;
    const auto n = static_cast<unsigned int>(rawKey.rawSize() * 8);
    if (n >= 256)
    {
      n_bits = 256;
    }
    else if (n >= 192)
    {
      n_bits = 192;
    }
    else if (n >= 128)
    {
      n_bits = 128;
    }
    else
    {
      LOG_FATAL_FMT("Need at least {} bits, only have {}", 128, n);
    }

    int rc = mbedtls_gcm_setkey(
      reinterpret_cast<mbedtls_gcm_context*>(ctx),
      MBEDTLS_CIPHER_ID_AES,
      rawKey.p,
      n_bits);

    if (rc != 0)
    {
      LOG_FATAL_FMT(tls::error_string(rc));
    }
  }

  KeyAesGcm::KeyAesGcm(KeyAesGcm&& that)
  {
    ctx = that.ctx;
    that.ctx = nullptr;
  }

  KeyAesGcm::~KeyAesGcm()
  {
    if (ctx)
    {
      auto ctx_ = reinterpret_cast<mbedtls_gcm_context*>(ctx);
      mbedtls_gcm_free(ctx_);
      delete ctx_;
    }
  }

  void KeyAesGcm::encrypt(
    CBuffer iv,
    CBuffer plain,
    CBuffer aad,
    uint8_t* cipher,
    uint8_t tag[GCM_SIZE_TAG]) const
  {
    int rc = mbedtls_gcm_crypt_and_tag(
      reinterpret_cast<mbedtls_gcm_context*>(ctx),
      MBEDTLS_GCM_ENCRYPT,
      plain.n,
      iv.p,
      iv.n,
      aad.p,
      aad.n,
      plain.p,
      cipher,
      GCM_SIZE_TAG,
      tag);

    if (rc != 0)
    {
      LOG_FATAL_FMT(tls::error_string(rc));
    }
  }

  bool KeyAesGcm::decrypt(
    CBuffer iv,
    const uint8_t tag[GCM_SIZE_TAG],
    CBuffer cipher,
    CBuffer aad,
    uint8_t* plain) const
  {
    return !mbedtls_gcm_auth_decrypt(
      reinterpret_cast<mbedtls_gcm_context*>(ctx),
      cipher.n,
      iv.p,
      iv.n,
      aad.p,
      aad.n,
      tag,
      GCM_SIZE_TAG,
      cipher.p,
      plain);
  }
}
