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

  struct WrappedLedgerSecret
  {
    std::vector<uint8_t> encrypted_data;

    // In most cases (e.g. re-key, member retirement), this is unset and the
    // version at which the ledger secret is applicable from is derived from the
    // version at which the recovery hook is triggered. In other cases (service
    // open or in recovery), a new ledger secret is created to protect the
    // integrity on the public-only transactions. However, the corresponding
    // shares are only written at a later version, once the previous ledger
    // secrets have been recovered.
    std::optional<kv::Version> version = std::nullopt;

    MSGPACK_DEFINE(encrypted_data, version)
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(WrappedLedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(WrappedLedgerSecret, encrypted_data)
  DECLARE_JSON_OPTIONAL_FIELDS(WrappedLedgerSecret, version)

  struct RecoverySharesInfo
  {
    // Latest ledger secret wrapped with the ledger secret wrapping key
    WrappedLedgerSecret wrapped_latest_ledger_secret;

    // Recovery shares encrypted with each active recovery member's public
    // encryption key
    EncryptedSharesMap encrypted_shares;

    MSGPACK_DEFINE(wrapped_latest_ledger_secret, encrypted_shares);
  };

  DECLARE_JSON_TYPE(RecoverySharesInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    RecoverySharesInfo, wrapped_latest_ledger_secret, encrypted_shares)

  struct EncryptedPastLedgerSecretInfo
  {
    // Past ledger secret encrypted with the latest ledger secret
    std::vector<uint8_t> encrypted_data;

    // Version at which the ledger secret is applicable from
    kv::Version version;

    // Version at which the ledger secret was written to the store
    // TODO: Unused for now
    kv::Version stored_version = kv::NoVersion;

    MSGPACK_DEFINE(encrypted_data, version, stored_version)
  };

  DECLARE_JSON_TYPE(EncryptedPastLedgerSecretInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    EncryptedPastLedgerSecretInfo, encrypted_data, version, stored_version)

  // The following two tables are distinct because some operations trigger a
  // re-share without requiring the ledger secrets to be updated (e.g. updating
  // the recovery threshold), and vice versa (e.g. ledger rekey). For historical
  // queries, when recovering ledger secrets from the ledger, the version at
  // which the previous ledger secret was _written_ to the store must be known
  // and can be deduced to the version at which the
  // EncryptedPastLedgerSecret map was updated.

  // The key for this table is always 0. It is updated every time the member
  // recovery shares are updated, e.g. when the recovery threshold is modified
  using RecoveryShares = kv::Map<size_t, RecoverySharesInfo>;

  // The key for this table is always 0. It is updated every time the ledger
  // secrets are updated, e.g. at startup or on ledger rekey
  using EncryptedPastLedgerSecret =
    kv::Map<size_t, EncryptedPastLedgerSecretInfo>;
}