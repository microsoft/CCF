// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/research/get_ledger_signing_mode.h"

namespace ccf
{
  LedgerSignMode get_ledger_signing_mode()
  {
    return LedgerSignMode::COSE;
  }

  bool get_allow_dual_signing_joinee()
  {
    return true;
  }
}
