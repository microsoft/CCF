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

  DECLARE_JSON_TYPE(EncryptedShare)
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedShare, nonce, encrypted_share)

  using EncryptedSharesMap = std::map<MemberId, EncryptedShare>;

  struct KeyShareInfo
  {
    // For now, only one encrypted ledger secret is stored in the ledger
    std::vector<uint8_t> encrypted_ledger_secret;
    EncryptedSharesMap encrypted_shares;

    MSGPACK_DEFINE(encrypted_ledger_secret, encrypted_shares);
  };

  // The key for this table will always be 0 since we never need to access
  // historical key shares info since all ledger secrets since the beginning of
  // time are re-encrypted each time the service issues new shares.
  using Shares = Store::Map<size_t, KeyShareInfo>;
}