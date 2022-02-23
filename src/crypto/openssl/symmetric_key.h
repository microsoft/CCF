// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/symmetric_key.h"
#include "openssl_wrappers.h"

#include <openssl/crypto.h>

namespace crypto
{
  class KeyAesGcm_OpenSSL : public KeyAesGcm
  {
  private:
    const std::vector<uint8_t> key;
    const EVP_CIPHER* evp_cipher;
    const EVP_CIPHER* evp_cipher_wrap_pad;

  public:
    KeyAesGcm_OpenSSL(std::span<const uint8_t> rawKey);
    KeyAesGcm_OpenSSL(const KeyAesGcm_OpenSSL& that) = delete;
    KeyAesGcm_OpenSSL(KeyAesGcm_OpenSSL&& that);
    virtual ~KeyAesGcm_OpenSSL()
    {
      OPENSSL_cleanse(const_cast<uint8_t*>(key.data()), key.size());
    }

    virtual size_t key_size() const override;

    virtual void encrypt(
      std::span<const uint8_t> iv,
      std::span<const uint8_t> plain,
      std::span<const uint8_t> aad,
      std::vector<uint8_t>& cipher,
      uint8_t tag[GCM_SIZE_TAG]) const override;

    virtual bool decrypt(
      std::span<const uint8_t> iv,
      const uint8_t tag[GCM_SIZE_TAG],
      std::span<const uint8_t> cipher,
      std::span<const uint8_t> aad,
      std::vector<uint8_t>& plain) const override;

    // @brief RFC 5649 AES key wrap with padding (CKM_AES_KEY_WRAP_PAD)
    // @param plain Plaintext key to wrap
    std::vector<uint8_t> ckm_aes_key_wrap_pad(
      std::span<const uint8_t> plain) const;

    // @brief RFC 5649 AES key unwrap (with padding, CKM_AES_KEY_WRAP_PAD)
    // @param cipher Wrapped key to unwrap
    std::vector<uint8_t> ckm_aes_key_unwrap_pad(
      std::span<const uint8_t> cipher) const;
  };
}
