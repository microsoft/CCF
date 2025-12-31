// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/entity_id.h"
#include "ccf/service/map.h"

#include <cstdint>
#include <map>
#include <vector>

namespace ccf
{
  struct WrappedSealedLedgerSecret
  {
    std::vector<uint8_t> wrapped_latest_ledger_secret;
    std::map<NodeId, std::vector<uint8_t>> encrypted_wrapping_keys;
  };

  DECLARE_JSON_TYPE(WrappedSealedLedgerSecret);
  DECLARE_JSON_REQUIRED_FIELDS(
    WrappedSealedLedgerSecret,
    wrapped_latest_ledger_secret,
    encrypted_wrapping_keys);

  using SealedLedgerSecrets = ServiceValue<WrappedSealedLedgerSecret>;
  namespace Tables
  {
    static constexpr auto SEALED_LEDGER_SECRETS =
      "public:ccf.gov.sealed_ledger_secrets";
  }
}