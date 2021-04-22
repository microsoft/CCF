// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "service_map.h"

#include <vector>

namespace ccf
{
  struct EncryptedLedgerSecret
  {
    // Version at which the ledger secret is applicable from (recovery
    // only)
    std::optional<kv::Version> version;

    // Encrypted secret for each backup
    std::vector<uint8_t> encrypted_secret = {};

    // Version at which the previous secret is stored at
    std::optional<kv::Version> previous_secret_stored_version = std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EncryptedLedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedLedgerSecret, version, encrypted_secret)
  DECLARE_JSON_OPTIONAL_FIELDS(
    EncryptedLedgerSecret, previous_secret_stored_version)

  using EncryptedLedgerSecrets = std::vector<EncryptedLedgerSecret>;
  using LedgerSecretsForNodes = std::map<NodeId, EncryptedLedgerSecrets>;

  // This map is used to communicate encrypted ledger secrets from the primary
  // to the backups during recovery (past secrets) and re-keying (new secret)
  using Secrets = ServiceMap<size_t, LedgerSecretsForNodes>;
}
