// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "kv/kv_types.h"

namespace kv
{
  // NullTxEncryptor does not decrypt or verify integrity
  class NullTxEncryptor : public kv::AbstractTxEncryptor
  {
  public:
    void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      kv::Version version) override
    {
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr = {};
      serialised_header = std::move(gcm_hdr.serialise());
      cipher = plain;
    }

    bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      kv::Version version) override
    {
      plain = cipher;
      return true;
    }

    void set_iv_id(size_t id) override {}

    size_t get_header_length() override
    {
      return crypto::GcmHeader<crypto::GCM_SIZE_IV>::RAW_DATA_SIZE;
    }

    void update_encryption_key(
      kv::Version version, const std::vector<uint8_t>& raw_ledger_key) override
    {}

    void rollback(kv::Version version) override {}
    void compact(kv::Version version) override {}
  };
}