// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"
#include "kv/map.h"

#include <map>
#include <msgpack/msgpack.hpp>
#include <vector>

namespace ccf
{
  using EncryptedShare = std::vector<uint8_t>;
  using EncryptedSharesMap = std::map<MemberId, EncryptedShare>;

  struct EncryptedLedgerSecret
  {
    // In most cases (e.g. re-key, member retirement), this is unset
    // (kv::NoVersion), and the version at which the ledger secret is applicable
    // from is derived from the local hook on recovery.
    // In one case (i.e. after recovery of the public ledger), a new ledger
    // secret is created to protect the integrity on the public-only
    // transactions. However, the corresponding shares are only written at a
    // later version, once the previous ledger secrets have been restored.
    kv::Version version;

    std::vector<uint8_t> encrypted_data;

    MSGPACK_DEFINE(version, encrypted_data)
  };

  DECLARE_JSON_TYPE(EncryptedLedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedLedgerSecret, version, encrypted_data)

  struct RecoverySharesInfo
  {
    // Keeping track of the latest and penultimate ledger secret allows the
    // value of this table to remain at a constant size through the lifetime of
    // the service. On recovery, a local hook on this table allows the service
    // to reconstruct the history of encrypted ledger secrets which are
    // decrypted in sequence once the ledger secret wrapping key is
    // re-assembled.

    // Latest ledger secret wrapped with the ledger secret wrapping key
    EncryptedLedgerSecret wrapped_latest_ledger_secret;

    // Previous ledger secret encrypted with the latest ledger secret
    EncryptedLedgerSecret encrypted_previous_ledger_secret;

    EncryptedSharesMap encrypted_shares;

    MSGPACK_DEFINE(
      wrapped_latest_ledger_secret,
      encrypted_previous_ledger_secret,
      encrypted_shares);
  };

  DECLARE_JSON_TYPE(RecoverySharesInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    RecoverySharesInfo,
    wrapped_latest_ledger_secret,
    encrypted_previous_ledger_secret,
    encrypted_shares)

  // The key for this table will always be 0 since a live service never needs to
  // access historical recovery shares info.
  using Shares = kv::Map<size_t, RecoverySharesInfo>;
}