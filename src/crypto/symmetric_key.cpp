// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "symmetric_key.h"

#include "ds/logger.h"
#include "ds/thread_messaging.h"
#include "error.h"
#include "tls/error_string.h"

#include <mbedtls/aes.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>

namespace crypto
{
  KeyAesGcm::KeyAesGcm(CBuffer rawKey)
  {
    for (uint32_t i = 0; i < ctxs.size(); ++i)
    {
      ctxs[i] = new mbedtls_gcm_context;
      mbedtls_gcm_init(ctxs[i]);

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
        throw std::logic_error(
          fmt::format("Need at least {} bits, only have {}", 128, n));
      }

      int rc =
        mbedtls_gcm_setkey(ctxs[i], MBEDTLS_CIPHER_ID_AES, rawKey.p, n_bits);

      if (rc != 0)
      {
        throw std::logic_error(tls::error_string(rc));
      }
    }
  }

  KeyAesGcm::KeyAesGcm(KeyAesGcm&& that)
  {
    ctxs = that.ctxs;

    for (uint32_t i = 0; i < that.ctxs.size(); ++i)
    {
      that.ctxs[i] = nullptr;
    }
  }

  KeyAesGcm::~KeyAesGcm()
  {
    for (auto ctx : ctxs)
    {
      if (ctx != nullptr)
      {
        mbedtls_gcm_free(ctx);
        delete ctx;
      }
    }
  }

  void KeyAesGcm::encrypt(
    CBuffer iv,
    CBuffer plain,
    CBuffer aad,
    uint8_t* cipher,
    uint8_t tag[GCM_SIZE_TAG]) const
  {
    auto ctx = ctxs[thread_ids[std::this_thread::get_id()]];
    int rc = mbedtls_gcm_crypt_and_tag(
      ctx,
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
      throw std::logic_error(tls::error_string(rc));
    }
  }

  bool KeyAesGcm::decrypt(
    CBuffer iv,
    const uint8_t tag[GCM_SIZE_TAG],
    CBuffer cipher,
    CBuffer aad,
    uint8_t* plain) const
  {
    auto ctx = ctxs[thread_ids[std::this_thread::get_id()]];
    return !mbedtls_gcm_auth_decrypt(
      ctx,
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
