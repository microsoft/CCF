// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "ledger/filenames.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

namespace ccf
{
  // Random access to the bytes of a committed ledger prefix. Reads do not hold
  // any ledger lock, and only read the ledger entries within the requested
  // byte range.
  class AbstractCommittedLedgerPrefixReader
  {
  public:
    virtual ~AbstractCommittedLedgerPrefixReader() = default;

    [[nodiscard]] virtual size_t size() const = 0;

    // Returns the bytes [start, end) of the prefix, or nullopt if this range
    // is not within the prefix or could not be read
    [[nodiscard]] virtual std::optional<std::vector<uint8_t>> read(
      size_t start, size_t end) const = 0;
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

    virtual std::optional<ccf::ledger::CommittedLedgerPrefixRange>
    committed_ledger_prefix_range_with_idx(size_t idx) = 0;

    // Returns nullptr if this node cannot provide the committed prefix
    // containing exactly the entries [from, to]
    virtual std::unique_ptr<AbstractCommittedLedgerPrefixReader>
    open_committed_ledger_prefix(size_t from, size_t to) = 0;

    virtual size_t get_init_idx() = 0;
  };
}