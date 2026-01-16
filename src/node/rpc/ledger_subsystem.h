// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "host/ledger.h"
#include "node/rpc/ledger_interface.h"

namespace ccf
{
  class ReadLedgerSubsystem : public AbstractReadLedgerSubsystemInterface
  {
  protected:
    asynchost::Ledger& ledger;

  public:
    ReadLedgerSubsystem(asynchost::Ledger& ledger_) : ledger(ledger_) {}

    [[nodiscard]] std::optional<std::filesystem::path>
    committed_ledger_path_with_idx(size_t idx) override
    {
      return ledger.committed_ledger_path_with_idx(idx);
    }
  };
}
