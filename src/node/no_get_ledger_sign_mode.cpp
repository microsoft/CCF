// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/research/get_ledger_sign_mode.h"

namespace ccf
{
  LedgerSignMode __attribute__((weak)) get_ledger_sign_mode()
  {
    return LedgerSignMode::Dual;
  }

  bool __attribute__((weak)) get_allow_dual_signing_joinee()
  {
    return true;
  }
}
