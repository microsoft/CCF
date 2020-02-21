// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <map>
#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace ccf
{
  using KeyShareIndex = ObjectId;

  struct EncryptedShare
  {
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> encrypted_share;

    MSGPACK_DEFINE(nonce, encrypted_share);
  };

  using EncryptedSharesMap = std::map<MemberId, EncryptedShare>;

  struct KeyShareInfo
  {
    std::vector<uint8_t> encrypted_ledger_secret;
    EncryptedSharesMap encrypted_shares;

    MSGPACK_DEFINE(encrypted_ledger_secret, encrypted_shares);
  };

  using Shares = Store::Map<KeyShareIndex, KeyShareInfo>;
}