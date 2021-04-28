// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "ds/serialized.h"
#include "ds/thread_messaging.h"

namespace crypto
{
  constexpr size_t GCM_SIZE_KEY = 32;
  constexpr size_t GCM_SIZE_TAG = 16;
  constexpr size_t GCM_SIZE_IV = 12;

  template <size_t SIZE_IV = GCM_SIZE_IV>
  struct GcmHeader
  {
    uint8_t tag[GCM_SIZE_TAG] = {};
    uint8_t iv[SIZE_IV] = {};

    // 12 bytes IV with 8 LSB are unique sequence number
    // and 4 MSB are 4 LSB of term (with last bit indicating a snapshot)
    constexpr static uint8_t IV_DELIMITER = 8;
    constexpr static size_t RAW_DATA_SIZE = sizeof(tag) + sizeof(iv);

    GcmHeader() = default;
    GcmHeader(const std::vector<uint8_t>& data)
    {
      if (data.size() != RAW_DATA_SIZE)
      {
        throw std::logic_error("Incompatible IV size");
      }

      memcpy(tag, data.data(), sizeof(tag));
      memcpy(iv, data.data() + sizeof(tag), sizeof(iv));
    }

    void set_iv_seq(uint64_t seq)
    {
      *reinterpret_cast<uint64_t*>(iv) = seq;
    }

    void set_iv_term(uint64_t term)
    {
      if (term > 0x7FFFFFFF)
      {
        throw std::logic_error(fmt::format(
          "term should fit in 31 bits of IV. Value is: 0x{0:x}", term));
      }

      *reinterpret_cast<uint32_t*>(iv + IV_DELIMITER) =
        static_cast<uint32_t>(term);
    }

    void set_iv_snapshot(bool is_snapshot)
    {
      // Set very last bit in IV
      iv[SIZE_IV - 1] |= (is_snapshot << ((sizeof(uint8_t) * 8) - 1));
    }

    void set_iv(uint8_t* iv_, size_t size)
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

    uint64_t get_iv_int() const
    {
      return *reinterpret_cast<const uint64_t*>(iv);
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

    void deserialise(const std::vector<uint8_t>& serial_hdr)
    {
      auto data_ = serial_hdr.data();
      auto size = serial_hdr.size();

      memcpy(
        tag, serialized::read(data_, size, GCM_SIZE_TAG).data(), GCM_SIZE_TAG);
      memcpy(iv, serialized::read(data_, size, SIZE_IV).data(), SIZE_IV);
    }
  };

  struct GcmCipher
  {
    GcmHeader<> hdr;
    std::vector<uint8_t> cipher;

    GcmCipher() {}
    GcmCipher(size_t size) : cipher(size) {}

    std::vector<uint8_t> serialise()
    {
      std::vector<uint8_t> serial;
      auto space = GcmHeader<>::RAW_DATA_SIZE + cipher.size();
      serial.resize(space);

      auto data_ = serial.data();
      serialized::write(data_, space, hdr.tag, sizeof(hdr.tag));
      serialized::write(data_, space, hdr.iv, sizeof(hdr.iv));
      serialized::write(data_, space, cipher.data(), cipher.size());

      return serial;
    }

    void deserialise(const std::vector<uint8_t>& serial)
    {
      auto size = serial.size();
      auto data_ = serial.data();
      hdr = serialized::read(data_, size, GcmHeader<>::RAW_DATA_SIZE);
      cipher = serialized::read(data_, size, size);
    }
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
