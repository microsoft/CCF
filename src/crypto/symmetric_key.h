// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../ds/buffer.h"
#include "../ds/serialized.h"
#include "ds/thread_messaging.h"

struct mbedtls_gcm_context;

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
    // and 4 MSB are 4 LSB of unique id (Node id or View)
    constexpr static uint8_t IV_DELIMITER = 8;
    constexpr static size_t RAW_DATA_SIZE = sizeof(tag) + sizeof(iv);

    GcmHeader() = default;
    GcmHeader(const std::vector<uint8_t>& data)
    {
      if (data.size() != RAW_DATA_SIZE)
        throw std::logic_error("Incompatible IV size");

      memcpy(tag, data.data(), sizeof(tag));
      memcpy(iv, data.data() + sizeof(tag), sizeof(iv));
    }

    void set_iv_id(uint64_t id)
    {
      *reinterpret_cast<uint32_t*>(iv + IV_DELIMITER) =
        static_cast<uint32_t>(id);
    }

    void set_iv_seq(uint64_t seq)
    {
      *reinterpret_cast<uint64_t*>(iv) = seq;
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
  private:
    mutable std::
      array<mbedtls_gcm_context*, enclave::ThreadMessaging::max_num_threads>
        ctxs;

  public:
    KeyAesGcm(CBuffer rawKey);
    KeyAesGcm(const KeyAesGcm& that) = delete;
    KeyAesGcm(KeyAesGcm&& that);
    ~KeyAesGcm();

    void encrypt(
      CBuffer iv,
      CBuffer plain,
      CBuffer aad,
      uint8_t* cipher,
      uint8_t tag[GCM_SIZE_TAG]) const;

    bool decrypt(
      CBuffer iv,
      const uint8_t tag[GCM_SIZE_TAG],
      CBuffer cipher,
      CBuffer aad,
      uint8_t* plain) const;
  };
}
