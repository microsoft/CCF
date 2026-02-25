// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/entity_id.h"
#include "ccf/service/local_sealing.h"
#include "ccf/service/map.h"
#include "ccf/service/tables/recovery_decision_protocol.h"
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

  // Map from NodeId to SealedRecoveryKey for each node that supports local
  // sealing
  using SealedRecoveryKeys = ServiceMap<NodeId, ccf::SealedRecoveryKey>;

  using LocalSealingNodeIdMap = ServiceMap<sealing_recovery::Name, NodeId>;

  namespace Tables
  {
    static constexpr auto SEALED_SHARES = "public:ccf.internal.sealed_shares";
    static constexpr auto SEALED_RECOVERY_KEYS =
      "public:ccf.gov.nodes.sealed_recovery_keys";
    static constexpr auto LOCAL_SEALING_NODE_ID_MAP =
      "public:ccf.gov.nodes.local_sealing_node_id_map";
  }
}
