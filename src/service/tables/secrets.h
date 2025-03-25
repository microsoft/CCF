// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"
#include "kv/kv_types.h"

#include <vector>

namespace ccf
{
  struct EncryptedLedgerSecret
  {
    // Version at which the ledger secret is applicable from (recovery
    // only)
    std::optional<ccf::kv::Version> version;

    // Encrypted secret for each backup
    std::vector<uint8_t> encrypted_secret = {};

    // Version at which the previous secret is stored at
    std::optional<ccf::kv::Version> previous_secret_stored_version =
      std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EncryptedLedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedLedgerSecret, version, encrypted_secret)
  DECLARE_JSON_OPTIONAL_FIELDS(
    EncryptedLedgerSecret, previous_secret_stored_version)

  using EncryptedLedgerSecrets = std::vector<EncryptedLedgerSecret>;
  using LedgerSecretsForNodes = std::map<NodeId, EncryptedLedgerSecrets>;

  // This map is used to broadcast encrypted ledger secrets to all nodes, during
  // recovery (past secrets) and re-keying (new secret)
  using Secrets = ServiceValue<LedgerSecretsForNodes>;
  namespace Tables
  {
    static constexpr auto ENCRYPTED_LEDGER_SECRETS =
      "public:ccf.internal.encrypted_ledger_secrets";
  }
}
