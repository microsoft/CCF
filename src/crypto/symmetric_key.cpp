// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/mbedtls/symmetric_key.h"

#include "crypto/openssl/symmetric_key.h"

namespace crypto
{
  using namespace mbedtls;

  std::unique_ptr<KeyAesGcm> make_key_aes_gcm(CBuffer rawKey)
  {
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
    return std::make_unique<KeyAesGcm_mbedTLS>(rawKey);
#else
    return std::make_unique<KeyAesGcm_OpenSSL>(rawKey);
#endif
  }
}