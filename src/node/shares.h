// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"
#include "kv/map.h"

#include <map>
#include <msgpack/msgpack.hpp>
#include <optional>
#include <vector>

namespace ccf
{
  using EncryptedShare = std::vector<uint8_t>;
  using EncryptedSharesMap = std::map<MemberId, EncryptedShare>;

  struct RecoverySharesInfo
  {
    // Latest ledger secret wrapped with the ledger secret wrapping key
    std::vector<uint8_t> wrapped_latest_ledger_secret;

    // Recovery shares encrypted with each active recovery member's public
    // encryption key
    EncryptedSharesMap encrypted_shares;

    MSGPACK_DEFINE(wrapped_latest_ledger_secret, encrypted_shares);
  };

  DECLARE_JSON_TYPE(RecoverySharesInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    RecoverySharesInfo, wrapped_latest_ledger_secret, encrypted_shares)

  // TODO: Perhaps rename this??
  struct EncryptedPastLedgerSecretInfo
  {
    // Past ledger secret encrypted with the latest ledger secret
    std::vector<uint8_t> encrypted_data;

    // Version at which the ledger secret is applicable from
    kv::Version version;

    // Version at which the ledger secret was written to the store
    // TODO: Unused for now
    std::optional<kv::Version> stored_version = std::nullopt;

    // Version at which the _next_ ledger secret is applicable from
    // TODO: Paste larger comment from the top of this file
    std::optional<kv::Version> next_version = std::nullopt;

    MSGPACK_DEFINE(encrypted_data, version, stored_version, next_version)
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EncryptedPastLedgerSecretInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    EncryptedPastLedgerSecretInfo, encrypted_data, version)
  DECLARE_JSON_OPTIONAL_FIELDS(
    EncryptedPastLedgerSecretInfo, stored_version, next_version)

  // The following two tables are distinct because some operations trigger a
  // re-share without requiring the ledger secrets to be updated (e.g. updating
  // the recovery threshold), and vice versa (e.g. ledger rekey). For historical
  // queries, when recovering ledger secrets from the ledger, the version at
  // which the previous ledger secret was _written_ to the store must be known
  // and can be deduced to the version at which the
  // EncryptedPastLedgerSecret map was updated.

  // The key for this table is always 0. It is updated every time the member
  // recovery shares are updated, e.g. when the recovery threshold is modified
  // and when the ledger secret is updated
  using RecoveryShares = kv::Map<size_t, RecoverySharesInfo>;

  // The key for this table is always 0. It is updated every time the ledger
  // secret is updated, e.g. at startup or on ledger rekey. It is not updated on
  // a pure re-share.
  using EncryptedPastLedgerSecret =
    kv::Map<size_t, EncryptedPastLedgerSecretInfo>;
}