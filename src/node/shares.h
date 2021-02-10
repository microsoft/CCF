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

  struct PreviousLedgerSecretInfo
  {
    // Past ledger secret encrypted with the latest ledger secret
    std::vector<uint8_t> encrypted_data = {};

    // Version at which the ledger secret is applicable from
    kv::Version version = kv::NoVersion;

    // Version at which the ledger secret _before_ this one was written to the
    // store
    std::optional<kv::Version> previous_secret_stored_version = std::nullopt;

    PreviousLedgerSecretInfo() = default;

    PreviousLedgerSecretInfo(
      std::vector<uint8_t>&& encrypted_data_,
      kv::Version version_,
      std::optional<kv::Version> stored_version_) :
      encrypted_data(std::move(encrypted_data_)),
      version(version_),
      previous_secret_stored_version(stored_version_)
    {}

    bool operator==(const PreviousLedgerSecretInfo& other) const
    {
      return encrypted_data == other.encrypted_data &&
        version == other.version &&
        previous_secret_stored_version == other.previous_secret_stored_version;
    }

    bool operator!=(const PreviousLedgerSecretInfo& other) const
    {
      return !(*this == other);
    }

    MSGPACK_DEFINE(encrypted_data, version, previous_secret_stored_version)
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(PreviousLedgerSecretInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    PreviousLedgerSecretInfo, encrypted_data, version)
  DECLARE_JSON_OPTIONAL_FIELDS(
    PreviousLedgerSecretInfo, previous_secret_stored_version)

  struct EncryptedLedgerSecretInfo
  {
    // Previous ledger secret info, encrypted with the current ledger secret.
    // Unset on service opening.
    std::optional<PreviousLedgerSecretInfo> previous_ledger_secret =
      std::nullopt;

    // Version at which the _next_ ledger secret is applicable from
    // Note: In most cases (e.g. re-key, member retirement), this is unset and
    // the version at which the next ledger secret is applicable from is
    // derived from the local hook on recovery. In one case (i.e. after recovery
    // of the public ledger), a new ledger secret is created to protect the
    // integrity on the public-only transactions. However, the corresponding
    // shares are only written at a later version, once the previous ledger
    // secrets have been restored.
    std::optional<kv::Version> next_version = std::nullopt;

    MSGPACK_DEFINE(previous_ledger_secret, next_version)
  };

  // Note: Both fields are never empty at the same time
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EncryptedLedgerSecretInfo)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedLedgerSecretInfo)
#pragma clang diagnostic pop
  DECLARE_JSON_OPTIONAL_FIELDS(
    EncryptedLedgerSecretInfo, previous_ledger_secret, next_version)

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
  using EncryptedLedgerSecretsInfo = kv::Map<size_t, EncryptedLedgerSecretInfo>;
}