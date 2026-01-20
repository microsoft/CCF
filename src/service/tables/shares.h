// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

#include <map>
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

    // Version at which the previous ledger secret was written to the store
    std::optional<ccf::kv::Version> previous_secret_stored_version =
      std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(RecoverySharesInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    RecoverySharesInfo, wrapped_latest_ledger_secret, encrypted_shares);
  DECLARE_JSON_OPTIONAL_FIELDS(
    RecoverySharesInfo, previous_secret_stored_version);

  struct PreviousLedgerSecretInfo
  {
    // Past ledger secret encrypted with the latest ledger secret
    std::vector<uint8_t> encrypted_data;

    // Version at which the ledger secret is applicable from
    ccf::kv::Version version = ccf::kv::NoVersion;

    // Version at which the ledger secret _before_ this one was written to the
    // store
    std::optional<ccf::kv::Version> previous_secret_stored_version =
      std::nullopt;

    PreviousLedgerSecretInfo() = default;

    PreviousLedgerSecretInfo(
      std::vector<uint8_t>&& encrypted_data_,
      ccf::kv::Version version_,
      std::optional<ccf::kv::Version> stored_version_) :
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
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(PreviousLedgerSecretInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    PreviousLedgerSecretInfo, encrypted_data, version);
  DECLARE_JSON_OPTIONAL_FIELDS(
    PreviousLedgerSecretInfo, previous_secret_stored_version);

  struct EncryptedLedgerSecretInfo
  {
    // Previous ledger secret info, encrypted with the current ledger secret.
    // Unset on service opening.
    std::optional<PreviousLedgerSecretInfo> previous_ledger_secret =
      std::nullopt;

    // Version at which the _next_ ledger secret is applicable from
    // Note: In most cases (e.g. re-key, member removal), this is unset and
    // the version at which the next ledger secret is applicable from is
    // derived from the local hook on recovery. In one case (i.e. after recovery
    // of the public ledger), a new ledger secret is created to protect the
    // integrity on the public-only transactions. However, the corresponding
    // shares are only written at a later version, once the previous ledger
    // secrets have been restored.
    std::optional<ccf::kv::Version> next_version = std::nullopt;
  };

  // Note: Both fields are never empty at the same time
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EncryptedLedgerSecretInfo);
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedLedgerSecretInfo);
  DECLARE_JSON_OPTIONAL_FIELDS(
    EncryptedLedgerSecretInfo, previous_ledger_secret, next_version);

  // The following two tables are distinct because some operations trigger a
  // re-share without requiring the ledger secrets to be updated (e.g. updating
  // the recovery threshold), and vice versa (e.g. ledger rekey). For historical
  // queries, when recovering ledger secrets from the ledger, the version at
  // which the previous ledger secret was _written_ to the store must be known
  // and can be deduced to the version at which the
  // EncryptedPastLedgerSecret map was updated.

  // This table is updated every time the member recovery shares are updated,
  // e.g. when the recovery threshold is modified and when the ledger secret is
  // updated
  using RecoveryShares = ServiceValue<RecoverySharesInfo>;

  // This table is updated every time the ledger secret is updated, e.g. at
  // startup or on ledger rekey. It is not updated on a pure re-share.
  using EncryptedLedgerSecretsInfo = ServiceValue<EncryptedLedgerSecretInfo>;

  namespace Tables
  {
    static constexpr auto SHARES = "public:ccf.internal.recovery_shares";
    static constexpr auto ENCRYPTED_PAST_LEDGER_SECRET =
      "public:ccf.internal.historical_encrypted_ledger_secret";
  }
}