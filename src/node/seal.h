// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/serialized.h"
#include "enclave/interface.h"
#include "enclave/oe_shim.h"
#include "encryptor.h"
#include "kv/kv_types.h"
#include "ledger_secrets.h"
#include "tls/entropy.h"

#include <optional>

namespace ccf
{
  struct SealedData
  {
    crypto::GcmCipher encrypted_data;
    std::vector<uint8_t> key_info;

    std::vector<uint8_t> serialise()
    {
      std::vector<uint8_t> s;
      auto space = sizeof(size_t) + crypto::GcmHeader<>::RAW_DATA_SIZE +
        encrypted_data.cipher.size() + sizeof(size_t) + key_info.size();
      s.resize(space);

      auto data_ = s.data();
      serialized::write(
        data_,
        space,
        crypto::GcmHeader<>::RAW_DATA_SIZE + encrypted_data.cipher.size());
      serialized::write(
        data_,
        space,
        (const uint8_t*)&encrypted_data.hdr,
        crypto::GcmHeader<>::RAW_DATA_SIZE);
      serialized::write(
        data_,
        space,
        encrypted_data.cipher.data(),
        encrypted_data.cipher.size());

      serialized::write(data_, space, key_info.size());
      serialized::write(data_, space, key_info.data(), key_info.size());

      return s;
    }

    void deserialise(const std::vector<uint8_t>& data)
    {
      auto data_ = static_cast<const uint8_t*>(data.data());
      auto size = data.size();

      auto len = serialized::read<size_t>(data_, size);
      encrypted_data.hdr =
        serialized::read(data_, size, crypto::GcmHeader<>::RAW_DATA_SIZE);
      len -= crypto::GcmHeader<>::RAW_DATA_SIZE;
      encrypted_data.cipher = serialized::read(data_, size, len);

      auto key_info_len = serialized::read<size_t>(data_, size);
      key_info = serialized::read(data_, size, key_info_len);
    }
  };

  class Seal : public AbstractSeal
  {
  private:
    ringbuffer::WriterPtr to_host;

#ifndef VIRTUAL_ENCLAVE
    static constexpr oe_seal_policy_t policy = OE_SEAL_POLICY_UNIQUE;
#else
    // For virtual enclaves, seal key are hardcoded for consistent behaviour
    // This does not mean that sealing is secure on virtual enclaves!
    const std::vector<uint8_t> virtual_raw_seal_key =
      std::vector<uint8_t>(16, 0x45);
    const std::vector<uint8_t> virtual_key_info =
      std::vector<uint8_t>(512, 0x01);
#endif

  public:
    Seal(ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside())
    {}

    bool seal(kv::Version version, const std::vector<uint8_t>& data)
    {
      SealedData sealed_data = {};
      sealed_data.encrypted_data.cipher.resize(data.size());
      std::vector<uint8_t> serialised_sealed_data;

      // Retrieve seal key
      auto seal_key_and_info = get_seal_key();
      if (!seal_key_and_info.has_value())
        return false;

      LOG_TRACE_FMT("Seal key successfully retrieved");

      crypto::KeyAesGcm seal_key(CBuffer(
        seal_key_and_info->first.data(), seal_key_and_info->first.size()));

      sealed_data.key_info = seal_key_and_info->second;

      // Get random IV
      auto iv = tls::create_entropy()->random(
        sealed_data.encrypted_data.hdr.get_iv().n);
      std::copy(iv.begin(), iv.end(), sealed_data.encrypted_data.hdr.iv);

      // Encrypt data
      seal_key.encrypt(
        sealed_data.encrypted_data.hdr.get_iv(),
        CBuffer(data.data(), data.size()),
        CBuffer(),
        sealed_data.encrypted_data.cipher.data(),
        sealed_data.encrypted_data.hdr.tag);

      // Send serialised sealed data to host for disk storage
      RINGBUFFER_WRITE_MESSAGE(
        AdminMessage::sealed_secrets,
        to_host,
        version,
        sealed_data.serialise());

      return true;
    }

    std::optional<std::vector<uint8_t>> unseal(const std::vector<uint8_t>& data)
    {
      SealedData sealed_data;

      // Deserialise data
      sealed_data.deserialise(data);

      // Retrieve seal key using unserialised key info
      auto raw_seal_key = get_seal_key_from_keyinfo(sealed_data.key_info);
      if (!raw_seal_key.has_value())
        return {};

      LOG_DEBUG_FMT("Seal key successfully retrieved from key info");

      // Decrypt serialised
      crypto::KeyAesGcm seal_key(
        CBuffer(raw_seal_key->data(), raw_seal_key->size()));

      std::vector<uint8_t> plain(sealed_data.encrypted_data.cipher.size());
      if (!seal_key.decrypt(
            sealed_data.encrypted_data.hdr.get_iv(),
            sealed_data.encrypted_data.hdr.tag,
            CBuffer(
              sealed_data.encrypted_data.cipher.data(),
              sealed_data.encrypted_data.cipher.size()),
            CBuffer(),
            plain.data()))
      {
        LOG_FAIL_FMT("Decryption of sealed data failed");
        return {};
      }

      return plain;
    }

  private:
    std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
    get_seal_key()
    {
#ifdef VIRTUAL_ENCLAVE
      // Virtual enclaves return the dummy seal key and key info
      return std::make_pair(virtual_raw_seal_key, virtual_key_info);
#else
      uint8_t* seal_key;
      uint8_t* key_info;
      size_t seal_key_size = 0;
      size_t key_info_size = 0;

      auto result = oe_get_seal_key_by_policy(
        policy, &seal_key, &seal_key_size, &key_info, &key_info_size);
      if (result != OE_OK)
      {
        LOG_FAIL_FMT(
          "oe_get_seal_key_by_policy failed: {}", oe_result_str(result));
        return {};
      }

      auto seal_key_and_info = std::make_pair(
        std::vector<uint8_t>(seal_key, seal_key + seal_key_size),
        std::vector<uint8_t>(key_info, key_info + key_info_size));
      oe_free_key(seal_key, seal_key_size, key_info, key_info_size);

      return seal_key_and_info;
#endif
    }

    std::optional<std::vector<uint8_t>> get_seal_key_from_keyinfo(
      std::vector<uint8_t> key_info)
    {
#ifdef VIRTUAL_ENCLAVE
      return virtual_raw_seal_key;
#else
      uint8_t* seal_key;
      size_t seal_key_size = 0;

      auto result = oe_get_seal_key(
        key_info.data(), key_info.size(), &seal_key, &seal_key_size);
      if (result != OE_OK)
      {
        LOG_FAIL_FMT("oe_get_seal_key failed: {}", oe_result_str(result));
        return {};
      }
      auto key = std::vector<uint8_t>(seal_key, seal_key + seal_key_size);
      oe_free_key(seal_key, seal_key_size, NULL, 0);

      return key;
#endif
    }
  };
}