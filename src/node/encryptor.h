// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/symmetric_key.h"
#include "kv/encryptor.h"
#include "ledger_secrets.h"

namespace ccf
{
  struct TxGcmHeader : public crypto::GcmHeader<crypto::GCM_SIZE_IV>
  {
    using Base = crypto::GcmHeader<crypto::GCM_SIZE_IV>;
    using Base::Base;

    // 12 bytes IV with 8 LSB are unique sequence number
    // and 4 MSB are 4 LSB of term (with last bit indicating a snapshot)
    constexpr static uint8_t IV_DELIMITER = 8;

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

    uint64_t get_term() const
    {
      return *reinterpret_cast<const uint32_t*>(iv + IV_DELIMITER);
    }

    // TODO: This should be toggling a bit, based on is_snapshot
    void set_iv_snapshot(bool is_snapshot)
    {
      // Set very last bit in IV
      iv[crypto::GCM_SIZE_IV - 1] |=
        (is_snapshot << ((sizeof(uint8_t) * 8) - 1));
    }
  };

  using NodeEncryptor = kv::TxEncryptor<ccf::LedgerSecrets, TxGcmHeader>;
}