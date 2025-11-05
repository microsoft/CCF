// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"

#include <span>
#include <vector>

namespace ccf::crypto
{
  constexpr size_t GCM_DEFAULT_KEY_SIZE = 32;

  constexpr size_t GCM_SIZE_TAG = 16;

  struct GcmHeader
  {
    uint8_t tag[GCM_SIZE_TAG] = {};

    // Size does not change after construction
    std::vector<uint8_t> iv;

    GcmHeader(size_t iv_size);

    void set_iv(const uint8_t* data, size_t size);
    [[nodiscard]] std::span<const uint8_t> get_iv() const;

    [[nodiscard]] size_t serialised_size() const;
    std::vector<uint8_t> serialise();

    void deserialise(const std::vector<uint8_t>& ser);
    void deserialise(const uint8_t*& data, size_t& size);
  };

  template <size_t IV_BYTES>
  struct FixedSizeGcmHeader : public GcmHeader
  {
    static constexpr size_t IV_SIZE = IV_BYTES;

    FixedSizeGcmHeader() : GcmHeader(IV_SIZE) {}

    static size_t serialised_size()
    {
      return GCM_SIZE_TAG + IV_SIZE;
    }

    void set_random_iv(EntropyPtr entropy = ccf::crypto::get_entropy())
    {
      iv = entropy->random(IV_SIZE);
    }
  };

  // GcmHeader with 12-byte (96-bit) IV
  using StandardGcmHeader = FixedSizeGcmHeader<12>;

  struct GcmCipher
  {
    StandardGcmHeader hdr;
    std::vector<uint8_t> cipher;

    GcmCipher();
    GcmCipher(size_t size);

    std::vector<uint8_t> serialise();

    void deserialise(const std::vector<uint8_t>& serial);
  };

  class KeyAesGcm
  {
  public:
    KeyAesGcm() = default;
    virtual ~KeyAesGcm() = default;

    // AES-GCM encryption
    virtual void encrypt(
      std::span<const uint8_t> iv,
      std::span<const uint8_t> plain,
      std::span<const uint8_t> aad,
      std::vector<uint8_t>& cipher,
      uint8_t tag[GCM_SIZE_TAG]) const = 0;

    // AES-GCM decryption
    virtual bool decrypt(
      std::span<const uint8_t> iv,
      const uint8_t tag[GCM_SIZE_TAG],
      std::span<const uint8_t> cipher,
      std::span<const uint8_t> aad,
      std::vector<uint8_t>& plain) const = 0;

    // Key size in bits
    [[nodiscard]] virtual size_t key_size() const = 0;
  };

  std::unique_ptr<KeyAesGcm> make_key_aes_gcm(std::span<const uint8_t> rawKey);

  /** Check for unsupported AES key sizes
   * @p num_bits Key size in bits
   */
  inline void check_supported_aes_key_size(size_t num_bits)
  {
    if (num_bits != 128 && num_bits != 192 && num_bits != 256)
    {
      throw std::runtime_error("Unsupported key size");
    }
  }

  /** Default initialization vector for AES-GCM (12 zeroes) */
  static std::vector<uint8_t> default_iv(12, 0);

  /// AES-GCM Encryption with @p key of @p data
  /// @param key The key
  /// @param plaintext The data
  /// @param iv Intialization vector
  /// @param aad Additional authenticated data
  /// @return ciphertext
  std::vector<uint8_t> aes_gcm_encrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> plaintext,
    const std::vector<uint8_t>& iv = default_iv,
    const std::vector<uint8_t>& aad = {});

  /// AES-GCM Decryption with @p key of @p data
  /// @param key The key
  /// @param ciphertext The (encrypted) data
  /// @param iv Initialization vector
  /// @param aad Additional authenticated data
  /// @return plaintext
  std::vector<uint8_t> aes_gcm_decrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> ciphertext,
    const std::vector<uint8_t>& iv = default_iv,
    const std::vector<uint8_t>& aad = {});
}
