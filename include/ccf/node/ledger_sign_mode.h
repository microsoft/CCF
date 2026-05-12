// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <cstdint>

namespace ccf
{
  enum class LedgerSignMode : uint8_t
  {
    // Emit both traditional node signatures and COSE Sign1 signatures.
    // Accept join requests from nodes in any signing mode.
    Dual = 0,

    // Emit only COSE Sign1 signatures, but accept join requests from
    // nodes still running in Dual mode. Use during rolling upgrades.
    CoseAllowDualJoin = 1,

    // Emit only COSE Sign1 signatures and reject join requests from
    // nodes running in Dual mode. Final state after a completed upgrade.
    CoseOnly = 2
  };

  DECLARE_JSON_ENUM(
    LedgerSignMode,
    {{LedgerSignMode::Dual, "Dual"},
     {LedgerSignMode::CoseAllowDualJoin, "CoseAllowDualJoin"},
     {LedgerSignMode::CoseOnly, "CoseOnly"}});

  /** Can be optionally implemented by the application to set the ledger
   * signing mode.
   *
   * The default (weak) implementation returns LedgerSignMode::Dual.
   *
   * @return the desired ledger signing mode
   */
  LedgerSignMode get_ledger_sign_mode();
}
