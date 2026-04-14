// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>

namespace ccf
{
  enum class LedgerSignMode : uint8_t
  {
    Dual = 0,
    COSE = 1
  };

  /** Can be optionally implemented by the application to set the ledger
   * signing mode.
   *
   * When returning LedgerSignMode::Dual (the default), ledger signatures
   * contain both a traditional node signature and a COSE Sign1 signature.
   * When returning LedgerSignMode::COSE, only COSE Sign1 signatures are
   * emitted.
   *
   * @return the desired ledger signing mode
   */
  LedgerSignMode get_ledger_sign_mode();

  /** Can be optionally implemented by the application to control whether
   * nodes running in Dual signing mode are allowed to join this network.
   *
   * During a rolling upgrade from Dual to COSE-only, operators may want
   * to temporarily allow Dual joiners (returning true) and later disallow
   * them once all nodes have been upgraded (returning false).
   *
   * The default (weak) implementation returns true.
   *
   * @return true if Dual-mode nodes are allowed to join, false otherwise
   */
  bool get_allow_dual_signing_joinee();
}
