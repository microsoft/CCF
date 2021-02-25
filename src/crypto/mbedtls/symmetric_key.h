// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "mbedtls_wrappers.h"

namespace crypto
{
  class KeyAesGcm_mbedTLS : public KeyAesGcm
  {
  private:
    mutable std::
      array<mbedtls::GcmContext, threading::ThreadMessaging::max_num_threads>
        ctxs;

  public:
    KeyAesGcm_mbedTLS(CBuffer rawKey);
    KeyAesGcm_mbedTLS(const KeyAesGcm_mbedTLS& that) = delete;
    KeyAesGcm_mbedTLS(KeyAesGcm_mbedTLS&& that);
    virtual ~KeyAesGcm_mbedTLS() = default;

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
