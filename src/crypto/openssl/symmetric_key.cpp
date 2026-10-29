// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/symmetric_key.h"

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/symmetric_key.h"
#include "ds/internal_logger.h"

#include <algorithm>
#include <climits>
#include <openssl/aes.h>
#include <openssl/evp.h>

namespace ccf::crypto
{
  using namespace OpenSSL;

  static constexpr size_t KEY_SIZE_256 = 256;
  static constexpr size_t KEY_SIZE_192 = 192;
  static constexpr size_t KEY_SIZE_128 = 128;

  namespace
  {
    const EVP_CIPHER* get_gcm_cipher(std::span<const uint8_t> raw_key)
    {
      const auto n = static_cast<unsigned int>(raw_key.size() * CHAR_BIT);
      if (n >= KEY_SIZE_256)
      {
        return EVP_aes_256_gcm();
      }
      if (n >= KEY_SIZE_192)
      {
        return EVP_aes_192_gcm();
      }
      if (n >= KEY_SIZE_128)
      {
        return EVP_aes_128_gcm();
      }
      throw std::logic_error(
        fmt::format("Need at least {} bits, only have {}", KEY_SIZE_128, n));
    }

    const EVP_CIPHER* get_wrap_pad_cipher(std::span<const uint8_t> raw_key)
    {
      const auto n = static_cast<unsigned int>(raw_key.size() * CHAR_BIT);
      if (n >= KEY_SIZE_256)
      {
        return EVP_aes_256_wrap_pad();
      }
      if (n >= KEY_SIZE_192)
      {
        return EVP_aes_192_wrap_pad();
      }
      return EVP_aes_128_wrap_pad();
    }

    // A null output authenticates AAD; otherwise GCM emits each payload byte.
    void update_in_chunks(
      EVP_CIPHER_CTX* context, std::span<const uint8_t> input, uint8_t* output)
    {
      static_assert(GCM_MAX_UPDATE_SIZE > 0 && GCM_MAX_UPDATE_SIZE <= INT_MAX);
      while (!input.empty())
      {
        const auto chunk =
          input.first(std::min(input.size(), GCM_MAX_UPDATE_SIZE));
        // int rather than int32_t: must match EVP_CipherUpdate's int* out
        // parameter exactly, whatever width the platform gives int.
        int outl{0};
        // Dispatches to EVP_EncryptUpdate or EVP_DecryptUpdate according to
        // the initialized context.
        CHECK1(EVP_CipherUpdate(
          context,
          output,
          &outl,
          chunk.data(),
          static_cast<int>(chunk.size())));

        // As we use no padding, we expect the input and output lengths to
        // match.
        assert(output == nullptr || static_cast<size_t>(outl) == chunk.size());
        input = input.subspan(chunk.size());
        if (output != nullptr)
        {
          output += chunk.size();
        }
      }
    }

    void encrypt_with_context(
      EVP_CIPHER_CTX* context,
      std::span<const uint8_t> iv,
      std::span<const uint8_t> plain,
      std::span<const uint8_t> aad,
      std::span<uint8_t> cipher,
      uint8_t tag[GCM_SIZE_TAG])
    {
      if (aad.empty() && plain.empty())
      {
        throw std::logic_error("aad and plain cannot both be empty");
      }
      if (cipher.size() != plain.size())
      {
        throw std::logic_error(fmt::format(
          "AES-GCM ciphertext size {} does not match plaintext size {}",
          cipher.size(),
          plain.size()));
      }

      if (plain.size() > GCM_MAX_DATA_SIZE)
      {
        throw std::logic_error(fmt::format(
          "AES-GCM plaintext size {} exceeds the limit of {} bytes",
          plain.size(),
          GCM_MAX_DATA_SIZE));
      }

      CHECK1(EVP_CIPHER_CTX_ctrl(
        context, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr));
      CHECK1(
        EVP_EncryptInit_ex2(context, nullptr, nullptr, iv.data(), nullptr));

      update_in_chunks(context, aad, nullptr);
      update_in_chunks(context, plain, cipher.data());

      int final_outl{0};
      CHECK1(EVP_EncryptFinal_ex(context, nullptr, &final_outl));

      // With GCM, EncryptUpdate() produces the complete output because there
      // is no padding and the block size is 1.
      //
      // See https://docs.openssl.org/3.3/man3/EVP_EncryptInit/#aead-interface.
      assert(final_outl == 0);

      CHECK1(EVP_CIPHER_CTX_ctrl(
        context, EVP_CTRL_GCM_GET_TAG, GCM_SIZE_TAG, &tag[0]));
    }

    void encrypt_with_context(
      EVP_CIPHER_CTX* context,
      std::span<const uint8_t> iv,
      std::span<const uint8_t> plain,
      std::span<const uint8_t> aad,
      std::vector<uint8_t>& cipher,
      uint8_t tag[GCM_SIZE_TAG])
    {
      if (cipher.size() == plain.size())
      {
        encrypt_with_context(
          context, iv, plain, aad, std::span<uint8_t>(cipher), tag);
      }
      else
      {
        std::vector<uint8_t> output(plain.size());
        encrypt_with_context(
          context, iv, plain, aad, std::span<uint8_t>(output), tag);
        cipher = std::move(output);
      }
    }

    bool decrypt_with_context(
      EVP_CIPHER_CTX* context,
      std::span<const uint8_t> iv,
      const uint8_t tag[GCM_SIZE_TAG],
      std::span<const uint8_t> cipher,
      std::span<const uint8_t> aad,
      std::vector<uint8_t>& plain)
    {
      // Never produced by encrypt(), so fail authentication rather than throw
      if (cipher.size() > GCM_MAX_DATA_SIZE)
      {
        plain.clear();
        return false;
      }

      CHECK1(EVP_CIPHER_CTX_ctrl(
        context, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr));
      CHECK1(
        EVP_DecryptInit_ex2(context, nullptr, nullptr, iv.data(), nullptr));

      update_in_chunks(context, aad, nullptr);

      std::vector<uint8_t> plaintext(cipher.size());
      update_in_chunks(context, cipher, plaintext.data());

      void* tag_ptr = const_cast<void*>(static_cast<const void*>(tag));
      CHECK1(EVP_CIPHER_CTX_ctrl(
        context, EVP_CTRL_GCM_SET_TAG, GCM_SIZE_TAG, tag_ptr));

      plain.clear();

      int final_outl{0};
      if (EVP_DecryptFinal_ex(context, nullptr, &final_outl) != 1)
      {
        return false;
      }

      // With GCM, DecryptUpdate() produces the complete output because there
      // is no padding and the block size is 1.
      //
      // See https://docs.openssl.org/3.3/man3/EVP_EncryptInit/#aead-interface.
      assert(final_outl == 0);

      plain = std::move(plaintext);
      return true;
    }

    class AesGcmContext_OpenSSL : public KeyAesGcm::Context
    {
    private:
      Unique_EVP_CIPHER_CTX encrypt_context;
      Unique_EVP_CIPHER_CTX decrypt_context;

    public:
      AesGcmContext_OpenSSL(
        const EVP_CIPHER* cipher, std::span<const uint8_t> key)
      {
        CHECK1(EVP_EncryptInit_ex2(
          encrypt_context, cipher, key.data(), nullptr, nullptr));
        CHECK1(EVP_DecryptInit_ex2(
          decrypt_context, cipher, key.data(), nullptr, nullptr));
      }

      void encrypt(
        std::span<const uint8_t> iv,
        std::span<const uint8_t> plain,
        std::span<const uint8_t> aad,
        std::vector<uint8_t>& cipher,
        uint8_t tag[GCM_SIZE_TAG]) override
      {
        encrypt_with_context(encrypt_context, iv, plain, aad, cipher, tag);
      }

      void encrypt(
        std::span<const uint8_t> iv,
        std::span<const uint8_t> plain,
        std::span<const uint8_t> aad,
        std::span<uint8_t> cipher,
        uint8_t tag[GCM_SIZE_TAG]) override
      {
        encrypt_with_context(encrypt_context, iv, plain, aad, cipher, tag);
      }

      bool decrypt(
        std::span<const uint8_t> iv,
        const uint8_t tag[GCM_SIZE_TAG],
        std::span<const uint8_t> cipher,
        std::span<const uint8_t> aad,
        std::vector<uint8_t>& plain) override
      {
        return decrypt_with_context(
          decrypt_context, iv, tag, cipher, aad, plain);
      }
    };
  }

  KeyAesGcm_OpenSSL::KeyAesGcm_OpenSSL(std::span<const uint8_t> raw_key) :
    key(std::vector<uint8_t>(raw_key.data(), raw_key.data() + raw_key.size())),
    evp_cipher(get_gcm_cipher(raw_key)),
    evp_cipher_wrap_pad(get_wrap_pad_cipher(raw_key))
  {}

  KeyAesGcm_OpenSSL::~KeyAesGcm_OpenSSL()
  {
    OPENSSL_cleanse(const_cast<uint8_t*>(key.data()), key.size());
  }

  size_t KeyAesGcm_OpenSSL::key_size() const
  {
    return key.size() * CHAR_BIT;
  }

  std::unique_ptr<KeyAesGcm::Context> KeyAesGcm_OpenSSL::make_context() const
  {
    return std::make_unique<AesGcmContext_OpenSSL>(evp_cipher, key);
  }

  void KeyAesGcm_OpenSSL::encrypt(
    std::span<const uint8_t> iv,
    std::span<const uint8_t> plain,
    std::span<const uint8_t> aad,
    std::vector<uint8_t>& cipher,
    uint8_t tag[GCM_SIZE_TAG]) const
  {
    Unique_EVP_CIPHER_CTX context;
    CHECK1(
      EVP_EncryptInit_ex2(context, evp_cipher, key.data(), nullptr, nullptr));
    encrypt_with_context(context, iv, plain, aad, cipher, tag);
  }

  void KeyAesGcm_OpenSSL::encrypt(
    std::span<const uint8_t> iv,
    std::span<const uint8_t> plain,
    std::span<const uint8_t> aad,
    std::span<uint8_t> cipher,
    uint8_t tag[GCM_SIZE_TAG]) const
  {
    Unique_EVP_CIPHER_CTX context;
    CHECK1(
      EVP_EncryptInit_ex2(context, evp_cipher, key.data(), nullptr, nullptr));
    encrypt_with_context(context, iv, plain, aad, cipher, tag);
  }

  bool KeyAesGcm_OpenSSL::decrypt(
    std::span<const uint8_t> iv,
    const uint8_t tag[GCM_SIZE_TAG],
    std::span<const uint8_t> cipher,
    std::span<const uint8_t> aad,
    std::vector<uint8_t>& plain) const
  {
    Unique_EVP_CIPHER_CTX context;
    CHECK1(
      EVP_DecryptInit_ex2(context, evp_cipher, key.data(), nullptr, nullptr));
    return decrypt_with_context(context, iv, tag, cipher, aad, plain);
  }

  std::vector<uint8_t> KeyAesGcm_OpenSSL::ckm_aes_key_wrap_pad(
    std::span<const uint8_t> plain) const
  {
    if (plain.size() > AES_KEY_WRAP_PAD_MAX_SIZE)
    {
      throw std::logic_error(fmt::format(
        "AES key wrap input size {} exceeds the limit of {} bytes",
        plain.size(),
        AES_KEY_WRAP_PAD_MAX_SIZE));
    }
    const auto inl = static_cast<int>(plain.size());

    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    CHECK1(
      EVP_EncryptInit_ex(ctx, evp_cipher_wrap_pad, nullptr, nullptr, nullptr));
    CHECK1(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nullptr));
    CHECK1(EVP_EncryptUpdate(ctx, nullptr, &len, plain.data(), inl));
    std::vector<uint8_t> cipher(len);
    CHECK1(EVP_EncryptUpdate(ctx, cipher.data(), &len, plain.data(), inl));
    CHECK1(EVP_EncryptFinal_ex(ctx, nullptr, &len));
    return cipher;
  }

  std::vector<uint8_t> KeyAesGcm_OpenSSL::ckm_aes_key_unwrap_pad(
    std::span<const uint8_t> cipher) const
  {
    // Never produced by ckm_aes_key_wrap_pad(), whose output is bounded, and
    // not representable as the int length of the single update call.
    if (cipher.size() > INT_MAX)
    {
      throw std::logic_error(fmt::format(
        "AES key unwrap input size {} exceeds the limit of {} bytes",
        cipher.size(),
        INT_MAX));
    }
    const auto inl = static_cast<int>(cipher.size());

    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    CHECK1(
      EVP_DecryptInit_ex(ctx, evp_cipher_wrap_pad, nullptr, nullptr, nullptr));
    CHECK1(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nullptr));
    CHECK1(EVP_DecryptUpdate(ctx, nullptr, &len, cipher.data(), inl));
    std::vector<uint8_t> plain(len);
    CHECK1(EVP_DecryptUpdate(ctx, plain.data(), &len, cipher.data(), inl));
    plain.resize(len);
    if (EVP_DecryptFinal_ex(ctx, nullptr, &len) != 1)
    {
      plain.clear();
    }
    return plain;
  }
}
