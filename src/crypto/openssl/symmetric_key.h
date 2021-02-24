// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "openssl_wrappers.h"

namespace crypto
{
  class KeyAesGcm_OpenSSL : public KeyAesGcm
  {
  private:
    CBuffer key;
    const EVP_CIPHER* cipher;

  public:
    KeyAesGcm_OpenSSL(CBuffer rawKey);
    KeyAesGcm_OpenSSL(const KeyAesGcm_OpenSSL& that) = delete;
    KeyAesGcm_OpenSSL(KeyAesGcm_OpenSSL&& that);
    virtual ~KeyAesGcm_OpenSSL() = default;

    virtual void encrypt(
      CBuffer iv,
      CBuffer plain,
      CBuffer aad,
      uint8_t* cipher,
      uint8_t tag[GCM_SIZE_TAG]) const override;

    virtual bool decrypt(
      CBuffer iv,
      const uint8_t tag[GCM_SIZE_TAG],
      CBuffer cipher,
      CBuffer aad,
      uint8_t* plain) const override;
  };
}
