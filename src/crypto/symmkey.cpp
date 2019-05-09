// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "symmkey.h"

#include "error.h"

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>

namespace crypto
{
  KeyAesGcm::KeyAesGcm(CBuffer rawKey)
  {
    ctx = new mbedtls_gcm_context;
    mbedtls_gcm_init(reinterpret_cast<mbedtls_gcm_context*>(ctx));

    if (mbedtls_gcm_setkey(
          reinterpret_cast<mbedtls_gcm_context*>(ctx),
          MBEDTLS_CIPHER_ID_AES,
          rawKey.p,
          static_cast<unsigned int>(rawKey.rawSize() * 8)))
      throw crypto_error("Failed to set AES GCM key");
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
    if (mbedtls_gcm_crypt_and_tag(
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
          tag))
      throw crypto_error("AES GCM encryption failed.");
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
