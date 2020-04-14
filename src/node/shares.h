// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <map>
#include <msgpack/msgpack.hpp>
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

  struct LatestLedgerSecret
  {
    // This is mostly kv::NoVersio, as the version at which the ledger secret is
    // applicable from is derived from the hook. However, on recovery, after the
    // public ledger has been recovered, new ledger secret are created to
    // protect the integrity on the public-only transactions. The corresponding
    // shares at only written at a later version, one the previous ledger
    // secrets have been restored. This version indicates the end of the public
    // recovery version.
    kv::Version version;

    std::vector<uint8_t> encrypted_data;

    MSGPACK_DEFINE(version, encrypted_data)
  };

  struct KeyShareInfo
  {
    // TODO: This is the latest ledger secret encrypted with the ledger secret
    // wrapping key
    LatestLedgerSecret encrypted_ledger_secret;

    // TODO: This is the previous ledger secret encrypted with the latest ledger
    // secret
    std::vector<uint8_t>
      encrypted_previous_ledger_secret; // TODO: Better name for this

    EncryptedSharesMap encrypted_shares;

    MSGPACK_DEFINE(
      encrypted_ledger_secret,
      encrypted_previous_ledger_secret,
      encrypted_shares);
  };

  // The key for this table will always be 0 since we never need to access
  // historical key shares info since all ledger secrets since the beginning of
  // time are re-encrypted each time the service issues new shares.
  using Shares = Store::Map<size_t, KeyShareInfo>;
}