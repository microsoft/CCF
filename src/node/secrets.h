// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "rpc/jsonrpc.h"

#include <msgpack.hpp>
#include <vector>

namespace ccf
{
  struct EncryptedLedgerSecret
  {
    NodeId node_id;

    // Encrypted secret for each backup
    std::vector<uint8_t> encrypted_secret = {};

    MSGPACK_DEFINE(node_id, encrypted_secret);
  };

  DECLARE_JSON_TYPE(EncryptedLedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedLedgerSecret, node_id, encrypted_secret)

  struct EncryptedLedgerSecrets
  {
    std::vector<uint8_t> primary_public_encryption_key = {};
    std::vector<EncryptedLedgerSecret> secrets = {};

    MSGPACK_DEFINE(primary_public_encryption_key, secrets);
  };

  DECLARE_JSON_TYPE(EncryptedLedgerSecrets)
  DECLARE_JSON_REQUIRED_FIELDS(
    EncryptedLedgerSecrets, primary_public_encryption_key, secrets)

  // This map is used to communicate encrypted network secrets from the primary
  // to the backups during recovery (past secrets) and re-keying (new secrets)
  using Secrets = Store::Map<kv::Version, EncryptedLedgerSecrets>;
}
