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

  struct GcmHeader
  {
    uint8_t tag[GCM_SIZE_TAG] = {};

    // Size does not change after construction
    std::vector<uint8_t> iv;

    GcmHeader(size_t iv_size)
    {
      iv.resize(iv_size);
    }

    // TODO: Needed? Surely this _or_ deserialize?
    // GcmHeader(const uint8_t* data, size_t size)
    // {
    //   if (size != RAW_DATA_SIZE)
    //   {
    //     throw std::logic_error("Incompatible IV size");
    //   }

    //   memcpy(tag, data, sizeof(tag));
    //   memcpy(iv, data + sizeof(tag), sizeof(iv));
    // }

    // GcmHeader(const std::vector<uint8_t>& data) :
    //   GcmHeader(data.data(), data.size())
    // {}

    size_t serialised_size() const
    {
      return sizeof(tag) + iv.size();
    }

    void set_iv(const uint8_t* data, size_t size)
    {
      if (size != iv.size())
      {
        throw std::logic_error(
          fmt::format("Specified IV is not of size {}", iv.size()));
      }

      memcpy(iv.data(), data, size);
    }

    CBuffer get_iv() const
    {
      return {iv.data(), iv.size()};
    }

    std::vector<uint8_t> serialise()
    {
      auto space = serialised_size();
      std::vector<uint8_t> serial_hdr(space);

      auto data_ = serial_hdr.data();
      serialized::write(data_, space, tag, sizeof(tag));
      serialized::write(data_, space, iv.data(), iv.size());

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
      iv = serialized::read(data, size, iv.size());
    }
  };

  template <size_t IV_BYTES>
  struct FixedSizeGcmHeader : public GcmHeader
  {
    static constexpr size_t IV_SIZE = IV_BYTES;

    FixedSizeGcmHeader() : GcmHeader(IV_SIZE) {}
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
