// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/entity_id.h"
#include "ccf/service/map.h"
#include "shares.h"

#include <cstdint>
#include <map>
#include <vector>

namespace ccf
{
  using EncryptedSealedSharesMap = std::map<NodeId, EncryptedShare>;

  struct SealedSharesInfo
  {
    // Latest ledger wrapped with the ledger secret wrapping key
    std::vector<uint8_t> wrapped_latest_ledger_secret;

    // Encrypted ledger secret wrapping keys for each active node
    EncryptedSealedSharesMap encrypted_wrapping_keys;

    // Version at which the previous ledger secret was written to the store
    std::optional<ccf::kv::Version> previous_secret_stored_version =
      std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SealedSharesInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    SealedSharesInfo, wrapped_latest_ledger_secret, encrypted_wrapping_keys);
  DECLARE_JSON_OPTIONAL_FIELDS(
    SealedSharesInfo, previous_secret_stored_version);

  using SealedShares = ServiceValue<SealedSharesInfo>;
  namespace Tables
  {
    static constexpr auto SEALED_SHARES = "public:ccf.gov.sealed_shares";
  }
}