// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/symmetric_key.h"

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/symmetric_key.h"
#include "ds/internal_logger.h"

#include <array>
#include <climits>
#include <mutex>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <optional>

namespace ccf::crypto
{
  using namespace OpenSSL;

  static constexpr size_t KEY_SIZE_256 = 256;
  static constexpr size_t KEY_SIZE_192 = 192;
  static constexpr size_t KEY_SIZE_128 = 128;

  namespace
  {
    static constexpr size_t MAX_CACHED_CONTEXTS = 16;

    const char* get_gcm_cipher_name(std::span<const uint8_t> raw_key)
    {
      const auto n = static_cast<unsigned int>(raw_key.size() * CHAR_BIT);
      if (n >= KEY_SIZE_256)
      {
        return "AES-256-GCM";
      }
      if (n >= KEY_SIZE_192)
      {
        return "AES-192-GCM";
      }
      if (n >= KEY_SIZE_128)
      {
        return "AES-128-GCM";
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

    struct CachedContext
    {
      std::mutex lock;
      std::optional<Unique_EVP_CIPHER_CTX> context = std::nullopt;
      bool keyed = false;
    };

    class ContextLease
    {
    private:
      CachedContext* cached = nullptr;
      [[maybe_unused]] std::unique_lock<std::mutex> lock;
      std::optional<Unique_EVP_CIPHER_CTX> uncached = std::nullopt;
      EVP_CIPHER_CTX* context = nullptr;

    public:
      ContextLease(
        CachedContext& cached_, std::unique_lock<std::mutex>&& lock_) :
        cached(&cached_),
        lock(std::move(lock_))
      {
        if (!cached->context.has_value())
        {
          cached->context.emplace();
        }
        context = cached->context.value();
      }

      ContextLease() : uncached(std::in_place), context(uncached.value()) {}

      EVP_CIPHER_CTX* get()
      {
        return context;
      }

      void initialise(
        bool encrypt, const EVP_CIPHER* cipher, std::span<const uint8_t> key)
      {
        if (cached != nullptr && cached->keyed)
        {
          return;
        }

        if (encrypt)
        {
          CHECK1(
            EVP_EncryptInit_ex2(context, cipher, key.data(), nullptr, nullptr));
        }
        else
        {
          CHECK1(
            EVP_DecryptInit_ex2(context, cipher, key.data(), nullptr, nullptr));
        }

        if (cached != nullptr)
        {
          cached->keyed = true;
        }
      }
    };

    class ContextPool
    {
    private:
      const bool encrypt;
      std::array<CachedContext, MAX_CACHED_CONTEXTS> contexts;

    public:
      ContextPool(bool encrypt_) : encrypt(encrypt_) {}

      ContextLease acquire(
        const EVP_CIPHER* cipher, std::span<const uint8_t> key)
      {
        for (auto& cached : contexts)
        {
          std::unique_lock<std::mutex> lock(cached.lock, std::try_to_lock);
          if (lock.owns_lock())
          {
            ContextLease lease(cached, std::move(lock));
            lease.initialise(encrypt, cipher, key);
            return lease;
          }
        }

        ContextLease lease;
        lease.initialise(encrypt, cipher, key);
        return lease;
      }
    };
  }

  struct KeyAesGcm_OpenSSL::ContextPools
  {
    ContextPool encrypt{true};
    ContextPool decrypt{false};
  };

  KeyAesGcm_OpenSSL::KeyAesGcm_OpenSSL(std::span<const uint8_t> rawKey) :
    key(std::vector<uint8_t>(rawKey.data(), rawKey.data() + rawKey.size())),
    evp_cipher(EVP_CIPHER_fetch(nullptr, get_gcm_cipher_name(rawKey), nullptr)),
    evp_cipher_wrap_pad(get_wrap_pad_cipher(rawKey)),
    context_pools(std::make_unique<ContextPools>())
  {}

  KeyAesGcm_OpenSSL::KeyAesGcm_OpenSSL(KeyAesGcm_OpenSSL&& that) noexcept :
    key(std::move(that.key)),
    evp_cipher(std::move(that.evp_cipher)),
    evp_cipher_wrap_pad(that.evp_cipher_wrap_pad),
    context_pools(std::move(that.context_pools))
  {}

  KeyAesGcm_OpenSSL::~KeyAesGcm_OpenSSL()
  {
    context_pools.reset();
    OPENSSL_cleanse(const_cast<uint8_t*>(key.data()), key.size());
  }

  size_t KeyAesGcm_OpenSSL::key_size() const
  {
    return key.size() * CHAR_BIT;
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

    auto lease = context_pools->encrypt.acquire(evp_cipher, key);
    auto* ctx = lease.get();

    CHECK1(
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr));
    CHECK1(EVP_EncryptInit_ex2(ctx, nullptr, nullptr, iv.data(), nullptr));

    if (!aad.empty())
    {
      int aad_outl{0};
      CHECK1(
        EVP_EncryptUpdate(ctx, nullptr, &aad_outl, aad.data(), aad.size()));
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
    CHECK1(EVP_EncryptFinal_ex(ctx, nullptr, &final_outl));

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
    auto lease = context_pools->decrypt.acquire(evp_cipher, key);
    auto* ctx = lease.get();

    CHECK1(
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr));

    CHECK1(EVP_DecryptInit_ex2(ctx, nullptr, nullptr, iv.data(), nullptr));
    if (!aad.empty())
    {
      int aad_outl{0};
      CHECK1(
        EVP_DecryptUpdate(ctx, nullptr, &aad_outl, aad.data(), aad.size()));
    }

    std::vector<uint8_t> plaintext(cipher.size());
    if (!cipher.empty())
    {
      int plain_outl{0};
      CHECK1(EVP_DecryptUpdate(
        ctx, plaintext.data(), &plain_outl, cipher.data(), cipher.size()));

      // As we use no padding, we expect the input and output lengths to match.
      assert(static_cast<size_t>(plain_outl) == cipher.size());
    }

    void* tag_ptr = const_cast<void*>(static_cast<const void*>(tag));
    CHECK1(
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_SIZE_TAG, tag_ptr));

    int final_outl{0};
    if (EVP_DecryptFinal_ex(ctx, nullptr, &final_outl) != 1)
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
    CHECK1(
      EVP_EncryptInit_ex(ctx, evp_cipher_wrap_pad, nullptr, nullptr, nullptr));
    CHECK1(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nullptr));
    CHECK1(EVP_EncryptUpdate(ctx, nullptr, &len, plain.data(), plain.size()));
    std::vector<uint8_t> cipher(len);
    CHECK1(
      EVP_EncryptUpdate(ctx, cipher.data(), &len, plain.data(), plain.size()));
    CHECK1(EVP_EncryptFinal_ex(ctx, nullptr, &len));
    return cipher;
  }

  std::vector<uint8_t> KeyAesGcm_OpenSSL::ckm_aes_key_unwrap_pad(
    std::span<const uint8_t> cipher) const
  {
    int len = 0;
    Unique_EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    CHECK1(
      EVP_DecryptInit_ex(ctx, evp_cipher_wrap_pad, nullptr, nullptr, nullptr));
    CHECK1(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nullptr));
    CHECK1(EVP_DecryptUpdate(ctx, nullptr, &len, cipher.data(), cipher.size()));
    std::vector<uint8_t> plain(len);
    CHECK1(
      EVP_DecryptUpdate(ctx, plain.data(), &len, cipher.data(), cipher.size()));
    plain.resize(len);
    if (EVP_DecryptFinal_ex(ctx, nullptr, &len) != 1)
    {
      plain.clear();
    }
    return plain;
  }
}
