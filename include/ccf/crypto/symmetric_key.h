// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/buffer.h"
#include "ds/serialized.h"

// TODO: Move to cpp?
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <vector>

namespace crypto
{
  constexpr size_t GCM_DEFAULT_KEY_SIZE = 32;

  constexpr size_t GCM_SIZE_TAG = 16;
  constexpr size_t GCM_SIZE_IV = 12;

  template <size_t SIZE_IV = GCM_SIZE_IV>
  struct GcmHeader
  {
    uint8_t tag[GCM_SIZE_TAG] = {};
    uint8_t iv[SIZE_IV] = {};

    constexpr static size_t RAW_DATA_SIZE = sizeof(tag) + sizeof(iv);

    GcmHeader() = default;
    GcmHeader(const uint8_t* data, size_t size)
    {
      if (size != RAW_DATA_SIZE)
      {
        throw std::logic_error("Incompatible IV size");
      }

      memcpy(tag, data, sizeof(tag));
      memcpy(iv, data + sizeof(tag), sizeof(iv));
    }

    GcmHeader(const std::vector<uint8_t>& data) :
      GcmHeader(data.data(), data.size())
    {}

    void set_iv(const uint8_t* iv_, size_t size)
    {
      if (size != SIZE_IV)
      {
        throw std::logic_error(
          fmt::format("Specified IV is not of size {}", SIZE_IV));
      }

      memcpy(iv, iv_, size);
    }

    CBuffer get_iv() const
    {
      return {iv, SIZE_IV};
    }

    std::vector<uint8_t> serialise()
    {
      auto space = RAW_DATA_SIZE;
      std::vector<uint8_t> serial_hdr(space);

      auto data_ = serial_hdr.data();
      serialized::write(data_, space, tag, sizeof(tag));
      serialized::write(data_, space, iv, sizeof(iv));

      return serial_hdr;
    }

    void deserialise(const std::vector<uint8_t>& ser)
    {
      auto data = ser.data();
      auto size = ser.size();

      deserialise(data, size);
    }

    void deserialise(const uint8_t*& data, size_t& size)
    {
      memcpy(
        tag, serialized::read(data, size, GCM_SIZE_TAG).data(), GCM_SIZE_TAG);
      memcpy(iv, serialized::read(data, size, SIZE_IV).data(), SIZE_IV);
    }
  };

  struct GcmCipher
  {
    GcmHeader<> hdr;
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
      CBuffer iv,
      CBuffer plain,
      CBuffer aad,
      uint8_t* cipher,
      uint8_t tag[GCM_SIZE_TAG]) const = 0;

    // AES-GCM decryption
    virtual bool decrypt(
      CBuffer iv,
      const uint8_t tag[GCM_SIZE_TAG],
      CBuffer cipher,
      CBuffer aad,
      uint8_t* plain) const = 0;

    // Key size in bits
    virtual size_t key_size() const = 0;
  };

  std::unique_ptr<KeyAesGcm> make_key_aes_gcm(CBuffer rawKey);

  /** Check for unsupported AES key sizes
   * @p num_bits Key size in bits
   */
  inline void check_supported_aes_key_size(size_t num_bits)
  {
    if (num_bits != 128 && num_bits != 192 && num_bits != 256)
      throw std::runtime_error("unsupported key size");
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
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& iv = default_iv,
    const std::vector<uint8_t>& aad = {});

  /// AES-GCM Decryption with @p key of @p data
  /// @param key The key
  /// @param ciphertext The (encrypted) data
  /// @param iv Initialization vector
  /// @param aad Additional authenticated data
  /// @return plaintext
  std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& iv = default_iv,
    const std::vector<uint8_t>& aad = {});
}
