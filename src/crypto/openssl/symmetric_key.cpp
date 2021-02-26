// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "symmetric_key.h"

#include "../mbedtls/symmetric_key.h"
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
    key(std::vector<uint8_t>(rawKey.p, rawKey.p + rawKey.n)),
    evp_cipher(nullptr)
  {
    const auto n = static_cast<unsigned int>(rawKey.rawSize() * 8);
    if (n >= 256)
    {
      evp_cipher = EVP_aes_256_gcm();
    }
    else if (n >= 192)
    {
      evp_cipher = EVP_aes_192_gcm();
    }
    else if (n >= 128)
    {
      evp_cipher = EVP_aes_128_gcm();
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
    std::vector<uint8_t> cb(plain.n + GCM_SIZE_TAG);
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    CHECK1(EVP_EncryptInit_ex(ctx, evp_cipher, NULL, key.data(), iv.p));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.n, NULL));
    CHECK1(EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.p));
    if (aad.n > 0)
      CHECK1(EVP_EncryptUpdate(ctx, NULL, &len, aad.p, aad.n));
    CHECK1(EVP_EncryptUpdate(ctx, cb.data(), &len, plain.p, plain.n));
    CHECK1(EVP_EncryptFinal_ex(ctx, cb.data() + len, &len));
    CHECK1(
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_SIZE_TAG, &tag[0]));

    if (plain.n > 0)
      memcpy(cipher, cb.data(), plain.n);
  }

  bool KeyAesGcm_OpenSSL::decrypt(
    CBuffer iv,
    const uint8_t tag[GCM_SIZE_TAG],
    CBuffer cipher,
    CBuffer aad,
    uint8_t* plain) const
  {
    std::vector<uint8_t> pb(cipher.n + GCM_SIZE_TAG);

    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    CHECK1(EVP_DecryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.n, NULL));
    CHECK1(EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.p));
    if (aad.n > 0)
      CHECK1(EVP_DecryptUpdate(ctx, NULL, &len, aad.p, aad.n));
    CHECK1(EVP_DecryptUpdate(ctx, pb.data(), &len, cipher.p, cipher.n));
    CHECK1(EVP_CIPHER_CTX_ctrl(
      ctx, EVP_CTRL_GCM_SET_TAG, GCM_SIZE_TAG, (uint8_t*)tag));

    int r = EVP_DecryptFinal_ex(ctx, pb.data() + len, &len) > 0;

    if (r == 1 && cipher.n > 0)
      memcpy(plain, pb.data(), cipher.n);

    return r == 1;
  }
}
