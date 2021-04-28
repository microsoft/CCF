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
      evp_cipher_wrap_pad = EVP_aes_256_wrap_pad();
    }
    else if (n >= 192)
    {
      evp_cipher = EVP_aes_192_gcm();
      evp_cipher_wrap_pad = EVP_aes_192_wrap_pad();
    }
    else if (n >= 128)
    {
      evp_cipher = EVP_aes_128_gcm();
      evp_cipher_wrap_pad = EVP_aes_128_wrap_pad();
    }
    else
    {
      throw std::logic_error(
        fmt::format("Need at least {} bits, only have {}", 128, n));
    }
  }

  size_t KeyAesGcm_OpenSSL::key_size() const
  {
    return key.size() * 8;
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
    CHECK1(EVP_EncryptInit_ex(ctx, evp_cipher, NULL, key.data(), NULL));
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

  std::vector<uint8_t> KeyAesGcm_OpenSSL::ckm_aes_key_wrap_pad(
    CBuffer plain) const
  {
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    CHECK1(EVP_EncryptInit_ex(ctx, evp_cipher_wrap_pad, NULL, NULL, NULL));
    CHECK1(EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), NULL));
    CHECK1(EVP_EncryptUpdate(ctx, NULL, &len, plain.p, plain.n));
    std::vector<uint8_t> cipher(len);
    CHECK1(EVP_EncryptUpdate(ctx, cipher.data(), &len, plain.p, plain.n));
    CHECK1(EVP_EncryptFinal_ex(ctx, NULL, &len));
    return cipher;
  }

  std::vector<uint8_t> KeyAesGcm_OpenSSL::ckm_aes_key_unwrap_pad(
    CBuffer cipher) const
  {
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    CHECK1(EVP_DecryptInit_ex(ctx, evp_cipher_wrap_pad, NULL, NULL, NULL));
    CHECK1(EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), NULL));
    CHECK1(EVP_DecryptUpdate(ctx, NULL, &len, cipher.p, cipher.n));
    std::vector<uint8_t> plain(len);
    CHECK1(EVP_DecryptUpdate(ctx, plain.data(), &len, cipher.p, cipher.n));
    plain.resize(len);
    if (EVP_DecryptFinal_ex(ctx, NULL, &len) != 1)
    {
      plain.clear();
    }
    return plain;
  }
}
