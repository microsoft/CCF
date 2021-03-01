// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/mbedtls/symmetric_key.h"

#include "crypto/openssl/symmetric_key.h"
#include "crypto/rsa_key_pair.h"
#include "symmetric_key.h"

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

  std::vector<uint8_t> aes_gcm_encrypt(
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad)
  {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
      throw std::runtime_error("unsupported key size");

    std::vector<uint8_t> r(plaintext.size());
    std::vector<uint8_t> tag(GCM_SIZE_TAG);
    auto k = make_key_aes_gcm(key);
    k->encrypt(iv, plaintext, aad, r.data(), tag.data());
    r.insert(r.end(), tag.begin(), tag.end());
    return r;
  }

  std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad)
  {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
      throw std::runtime_error("unsupported key size");
    if (ciphertext.size() <= GCM_SIZE_TAG)
      throw std::runtime_error("Not enough ciphertext");

    size_t ciphertext_length = ciphertext.size() - GCM_SIZE_TAG;
    std::vector<uint8_t> r(ciphertext_length);
    auto k = make_key_aes_gcm(key);
    k->decrypt(
      iv,
      ciphertext.data() + ciphertext_length,
      {ciphertext.data(), ciphertext_length},
      aad,
      r.data());
    return r;
  }
}
