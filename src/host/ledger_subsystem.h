// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "host/ledger.h"
#include "node/rpc/ledger_interface.h"

#include <filesystem>
#include <optional>

namespace asynchost
{
  // Host-owned adapter exposing the concrete ledger to the node through the
  // read-only subsystem interface. The host constructs it beside the ledger
  // and hands it to the enclave entry point, so the node never depends on the
  // ledger implementation.
  class ReadLedgerSubsystem : public ccf::AbstractReadLedgerSubsystemInterface
  {
  protected:
    Ledger& ledger;

  public:
    ReadLedgerSubsystem(Ledger& ledger_) : ledger(ledger_) {}

    [[nodiscard]] std::optional<std::filesystem::path>
    committed_ledger_path_with_idx(size_t idx) override
    {
      return ledger.committed_ledger_path_with_idx(idx);
    }

    [[nodiscard]] size_t get_init_idx() override
    {
      return ledger.get_init_idx();
    }
  };
}
