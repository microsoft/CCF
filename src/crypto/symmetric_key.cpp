// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/symmetric_key.h"

#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/symmetric_key.h"
#include "ds/serialized.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::crypto
{
  /// GcmHeader implementation
  GcmHeader::GcmHeader(size_t iv_size)
  {
    iv.resize(iv_size);
  }

  void GcmHeader::set_iv(const uint8_t* data, size_t size)
  {
    if (size != iv.size())
    {
      throw std::logic_error(
        fmt::format("Specified IV is not of size {}", iv.size()));
    }

    memcpy(iv.data(), data, size);
  }

  std::span<const uint8_t> GcmHeader::get_iv() const
  {
    return iv;
  }

  size_t GcmHeader::serialised_size() const
  {
    return sizeof(tag) + iv.size();
  }

  std::vector<uint8_t> GcmHeader::serialise()
  {
    auto space = serialised_size();
    std::vector<uint8_t> serial_hdr(space);

    auto* data_ = serial_hdr.data();
    serialized::write(data_, space, static_cast<uint8_t*>(tag), sizeof(tag));
    serialized::write(data_, space, iv.data(), iv.size());

    return serial_hdr;
  }

  void GcmHeader::deserialise(const std::vector<uint8_t>& ser)
  {
    const auto* data = ser.data();
    auto size = ser.size();

    deserialise(data, size);
  }

  void GcmHeader::deserialise(const uint8_t*& data, size_t& size)
  {
    memcpy(
      static_cast<uint8_t*>(tag),
      serialized::read(data, size, GCM_SIZE_TAG).data(),
      GCM_SIZE_TAG);
    iv = serialized::read(data, size, iv.size());
  }

  /// GcmCipher implementation
  GcmCipher::GcmCipher() = default;

  GcmCipher::GcmCipher(size_t size) : cipher(size) {}

  std::vector<uint8_t> GcmCipher::serialise()
  {
    std::vector<uint8_t> serial;
    auto space = StandardGcmHeader::serialised_size() + cipher.size();
    serial.resize(space);

    auto* data_ = serial.data();
    serialized::write(
      data_, space, static_cast<uint8_t*>(hdr.tag), sizeof(hdr.tag));
    serialized::write(data_, space, hdr.iv.data(), hdr.iv.size());
    serialized::write(data_, space, cipher.data(), cipher.size());

    return serial;
  }

  void GcmCipher::deserialise(const std::vector<uint8_t>& serial)
  {
    const auto* data = serial.data();
    auto size = serial.size();
    hdr.deserialise(data, size);
    cipher = serialized::read(data, size, size);
  }

  /// Free function implementation
  std::unique_ptr<KeyAesGcm> make_key_aes_gcm(std::span<const uint8_t> rawKey)
  {
    return std::make_unique<KeyAesGcm_OpenSSL>(rawKey);
  }
}
