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

    [[nodiscard]] std::optional<CommittedLedgerPrefixRange>
    committed_ledger_prefix_range_with_idx(size_t idx) override
    {
      const auto range = ledger.committed_ledger_prefix_range_with_idx(idx);
      if (!range.has_value())
      {
        return std::nullopt;
      }

      return CommittedLedgerPrefixRange{
        .start_idx = range->first, .end_idx = range->second};
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>>
    read_committed_ledger_prefix(size_t from, size_t to) override
    {
      return ledger.read_committed_ledger_prefix(from, to);
    }

    [[nodiscard]] size_t get_init_idx() override
    {
      return ledger.get_init_idx();
    }
  };
}
