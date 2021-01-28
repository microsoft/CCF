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

  // TODO: To unify with secrets.h encrypted ledger secret??
  struct PreviousEncryptedLedgerSecret
  {
    std::vector<uint8_t> encrypted_data;

    kv::Version version;

    MSGPACK_DEFINE(encrypted_data, version)
  };

  DECLARE_JSON_TYPE(PreviousEncryptedLedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(
    PreviousEncryptedLedgerSecret, encrypted_data, version)

  struct RecoverySharesInfo
  {
    // Keeping track of the latest and penultimate ledger secret allows the
    // value of this table to remain at a constant size through the lifetime of
    // the service. On recovery, a local hook on this table allows the service
    // to reconstruct the history of encrypted ledger secrets which are
    // decrypted in sequence once the ledger secret wrapping key is
    // re-assembled.

    // Latest ledger secret wrapped with the ledger secret wrapping key
    WrappedLedgerSecret wrapped_latest_ledger_secret;

    // Previous ledger secret encrypted with the latest ledger secret
    PreviousEncryptedLedgerSecret encrypted_previous_ledger_secret;

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