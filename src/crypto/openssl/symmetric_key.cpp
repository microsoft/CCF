// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "symmetric_key.h"

#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "ds/thread_messaging.h"

#include <openssl/aes.h>
#include <openssl/evp.h>

namespace crypto
{
  using namespace OpenSSL;

  KeyAesGcm_OpenSSL::KeyAesGcm_OpenSSL(CBuffer rawKey) :
    key(rawKey),
    cipher(nullptr)
  {
    const auto n = static_cast<unsigned int>(rawKey.rawSize() * 8);
    if (n >= 256)
    {
      cipher = EVP_aes_256_gcm();
    }
    else if (n >= 192)
    {
      cipher = EVP_aes_192_gcm();
    }
    else if (n >= 128)
    {
      cipher = EVP_aes_128_gcm();
    }
    else
    {
      throw std::logic_error(
        fmt::format("Need at least {} bits, only have {}", 128, n));
    }
  }

  void KeyAesGcm_OpenSSL::encrypt(
    CBuffer iv,
    CBuffer plain,
    CBuffer aad,
    uint8_t* cipher,
    uint8_t tag[GCM_SIZE_TAG]) const
  {
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    CHECK1(EVP_CipherInit_ex(ctx, this->cipher, NULL, key.p, iv.p, true));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.n, NULL));
    CHECK1(EVP_CipherInit_ex(ctx, NULL, NULL, key.p, iv.p, true));
    if (aad.n > 0)
      CHECK1(EVP_CipherUpdate(ctx, NULL, &len, aad.p, aad.n));
    CHECK1(EVP_CipherUpdate(ctx, cipher, &len, plain.p, plain.n));
    CHECK1(EVP_CipherFinal_ex(ctx, cipher, &len));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_SIZE_TAG, tag));
  }

  bool KeyAesGcm_OpenSSL::decrypt(
    CBuffer iv,
    const uint8_t tag[GCM_SIZE_TAG],
    CBuffer cipher,
    CBuffer aad,
    uint8_t* plain) const
  {
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    CHECK1(EVP_CipherInit_ex(ctx, this->cipher, NULL, NULL, NULL, false));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.n, NULL));
    CHECK1(EVP_CipherInit_ex(ctx, NULL, NULL, key.p, iv.p, false));
    if (aad.n > 0)
      CHECK1(EVP_CipherUpdate(ctx, NULL, &len, aad.p, aad.n));
    CHECK1(EVP_CipherUpdate(ctx, plain, &len, cipher.p, cipher.n));
    CHECK1(
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_SIZE_TAG, (void*)tag));
    return EVP_CipherFinal_ex(ctx, plain + len, &len) > 0;
  }
}
