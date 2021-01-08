// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
      kv::Version version,
      kv::Term term,
      bool is_snapshot = false) override
    {
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

    size_t get_header_length() override
    {
      return 0;
    }

    void update_encryption_key(
      kv::Version version, std::vector<uint8_t>&& raw_ledger_key) override
    {}

    void rollback(kv::Version version) override {}
    void compact(kv::Version version) override {}
  };
}