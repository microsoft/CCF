// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/symmetric_key.h"

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/logger.h"
#include "ds/thread_messaging.h"

#include <openssl/aes.h>
#include <openssl/evp.h>

namespace ccf::crypto
{
  using namespace OpenSSL;

  KeyAesGcm_OpenSSL::KeyAesGcm_OpenSSL(std::span<const uint8_t> rawKey) :
    key(std::vector<uint8_t>(rawKey.data(), rawKey.data() + rawKey.size())),
    evp_cipher(nullptr)
  {
    const auto n = static_cast<unsigned int>(rawKey.size() * 8);
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
    std::span<const uint8_t> iv,
    std::span<const uint8_t> plain,
    std::span<const uint8_t> aad,
    std::vector<uint8_t>& cipher,
    uint8_t tag[GCM_SIZE_TAG]) const
  {
    if (aad.empty() && plain.empty())
    {
      throw std::logic_error("aad and plain cannot both be empty");
    }

    Unique_EVP_CIPHER_CTX ctx;
    CHECK1(EVP_EncryptInit_ex(ctx, evp_cipher, NULL, key.data(), NULL));

    CHECK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL));
    CHECK1(EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()));

    if (!aad.empty())
    {
      int aad_outl{0};
      CHECK1(EVP_EncryptUpdate(ctx, NULL, &aad_outl, aad.data(), aad.size()));
    }

    std::vector<uint8_t> ciphertext(plain.size());
    if (!plain.empty())
    {
      int cypher_outl{0};
      CHECK1(EVP_EncryptUpdate(
        ctx, ciphertext.data(), &cypher_outl, plain.data(), plain.size()));

      // As we use no padding, we expect the input and output lengths to match.
      assert(static_cast<size_t>(cypher_outl) == plain.size());
    }

    int final_outl{0};
    CHECK1(EVP_EncryptFinal_ex(ctx, NULL, &final_outl));

    // As long a we use GSM cipher, the final outl must be 0, because there's no
    // padding and the block size is equal to 1, so EncryptUpdate() always does
    // the whole thing. Final is still a must to finalize and check the error.
    //
    // See https://docs.openssl.org/3.3/man3/EVP_EncryptInit/#aead-interface.
    assert(final_outl == 0);

    CHECK1(
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_SIZE_TAG, &tag[0]));

    if (!plain.empty())
    {
      cipher = std::move(ciphertext);
    }
  }

  bool KeyAesGcm_OpenSSL::decrypt(
    std::span<const uint8_t> iv,
    const uint8_t tag[GCM_SIZE_TAG],
    std::span<const uint8_t> cipher,
    std::span<const uint8_t> aad,
    std::vector<uint8_t>& plain) const
  {
    Unique_EVP_CIPHER_CTX ctx;
    CHECK1(EVP_DecryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL));

    CHECK1(EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()));
    if (!aad.empty())
    {
      int aad_outl{0};
      CHECK1(EVP_DecryptUpdate(ctx, NULL, &aad_outl, aad.data(), aad.size()));
    }

    std::vector<uint8_t> plaintext(cipher.size());
    if (!cipher.empty())
    {
      int plain_outl{0};
      CHECK1(EVP_DecryptUpdate(
        ctx, plaintext.data(), &plain_outl, cipher.data(), cipher.size()));

      // As we use no padding, we expect the input and output lengths to match.
      assert(plain_outl == cipher.size());
    }

    CHECK1(EVP_CIPHER_CTX_ctrl(
      ctx, EVP_CTRL_GCM_SET_TAG, GCM_SIZE_TAG, (uint8_t*)tag));

    int final_outl{0};
    if (EVP_DecryptFinal_ex(ctx, NULL, &final_outl) != 1)
    {
      return false;
    }

    // As long a we use GSM cipher, the final outl must be 0, because there's no
    // padding and the block size is equal to 1, so EncryptUpdate() always does
    // the whole thing. Final is still a must to finalize and check the error.
    //
    // See https://docs.openssl.org/3.3/man3/EVP_EncryptInit/#aead-interface.
    assert(final_outl == 0);

    if (!cipher.empty())
    {
      plain = std::move(plaintext);
    }

    return true;
  }

  std::vector<uint8_t> KeyAesGcm_OpenSSL::ckm_aes_key_wrap_pad(
    std::span<const uint8_t> plain) const
  {
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    CHECK1(EVP_EncryptInit_ex(ctx, evp_cipher_wrap_pad, NULL, NULL, NULL));
    CHECK1(EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), NULL));
    CHECK1(EVP_EncryptUpdate(ctx, NULL, &len, plain.data(), plain.size()));
    std::vector<uint8_t> cipher(len);
    CHECK1(
      EVP_EncryptUpdate(ctx, cipher.data(), &len, plain.data(), plain.size()));
    CHECK1(EVP_EncryptFinal_ex(ctx, NULL, &len));
    return cipher;
  }

  std::vector<uint8_t> KeyAesGcm_OpenSSL::ckm_aes_key_unwrap_pad(
    std::span<const uint8_t> cipher) const
  {
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    CHECK1(EVP_DecryptInit_ex(ctx, evp_cipher_wrap_pad, NULL, NULL, NULL));
    CHECK1(EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), NULL));
    CHECK1(EVP_DecryptUpdate(ctx, NULL, &len, cipher.data(), cipher.size()));
    std::vector<uint8_t> plain(len);
    CHECK1(
      EVP_DecryptUpdate(ctx, plain.data(), &len, cipher.data(), cipher.size()));
    plain.resize(len);
    if (EVP_DecryptFinal_ex(ctx, NULL, &len) != 1)
    {
      plain.clear();
    }
    return plain;
  }
}
