// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

namespace kv
{
  // NullTxEncryptor does not decrypt or verify integrity
  class NullTxEncryptor : public AbstractTxEncryptor
  {
  public:
    bool encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      const TxID& tx_id,
      bool is_snapshot = false) override
    {
      cipher = plain;
      return true;
    }

    bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      Version version,
      Term& term,
      bool historical_hint = false) override
    {
      plain = cipher;
      return true;
    }

    size_t get_header_length() override
    {
      return 0;
    }

    void rollback(Version version) override {}

    uint64_t get_term(const uint8_t* data, size_t size) override
    {
      return 0;
    }
  };
}