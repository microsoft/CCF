// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace ccf
{
  using KeyShareIndex = ObjectId;
  using EncryptedLedgerSecret = std::vector<uint8_t>;
  using EncryptedShare = std::vector<uint8_t>;

  struct KeyShareInfo
  {
    EncryptedLedgerSecret encrypted_ledger_secret;
    std::vector<EncryptedShare> encrypted_shares;

    MSGPACK_DEFINE(encrypted_ledger_secret, encrypted_shares);
  };

  using Shares = Store::Map<KeyShareIndex, KeyShareInfo>;
}