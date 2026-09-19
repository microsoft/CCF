// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <filesystem>
#include <optional>
#include <vector>

namespace ccf
{
  struct CommittedLedgerPrefixRange
  {
    size_t start_idx;
    size_t end_idx;
  };

  class AbstractReadLedgerSubsystemInterface : public AbstractNodeSubSystem
  {
  public:
    ~AbstractReadLedgerSubsystemInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "LedgerReadInterface";
    }

    virtual std::optional<std::filesystem::path> committed_ledger_path_with_idx(
      size_t idx) = 0;

    virtual std::optional<CommittedLedgerPrefixRange>
    committed_ledger_prefix_range_with_idx(size_t idx) = 0;

    virtual std::optional<std::vector<uint8_t>> read_committed_ledger_prefix(
      size_t from, size_t to) = 0;

    virtual size_t get_init_idx() = 0;
  };
}