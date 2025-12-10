// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/symmetric_key.h"
#include "kv/encryptor.h"
#include "ledger_secrets.h"

namespace ccf
{
  // Extends 12-byte IV GcmHeader with interpretation of those bytes as term,
  // seqno, and snapshot indicator:
  // - 8 LSB are unique sequence number
  // - 4 MSB (except final bit) are the 4 LSB of term
  // - Final bit indicates a snapshot
  struct TxGcmHeader : public ccf::crypto::StandardGcmHeader
  {
    using ccf::crypto::StandardGcmHeader::StandardGcmHeader;
    constexpr static uint8_t IV_DELIMITER = 8;

    void set_iv_seq(uint64_t seq)
    {
      *reinterpret_cast<uint64_t*>(iv.data()) = seq;
    }

    void set_iv_term(uint64_t term)
    {
      if (term > 0x7FFFFFFF)
      {
        throw std::logic_error(fmt::format(
          "term should fit in 31 bits of IV. Value is: 0x{0:x}", term));
      }

      *reinterpret_cast<uint32_t*>(iv.data() + IV_DELIMITER) =
        static_cast<uint32_t>(term);
    }

    [[nodiscard]] uint64_t get_term() const
    {
      return *reinterpret_cast<const uint32_t*>(iv.data() + IV_DELIMITER);
    }

    void set_iv_is_snapshot()
    {
      // Set very last bit in IV
      iv.back() |= (1 << ((sizeof(uint8_t) * 8) - 1));
    }
  };

  using NodeEncryptor = ccf::kv::TxEncryptor<ccf::LedgerSecrets, TxGcmHeader>;
}