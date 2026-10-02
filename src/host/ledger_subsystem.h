// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "host/ledger.h"
#include "node/rpc/ledger_interface.h"

#include <filesystem>
#include <memory>
#include <optional>

namespace asynchost
{
  class CommittedLedgerPrefixReader
    : public ccf::AbstractCommittedLedgerPrefixReader
  {
  private:
    LedgerFile::CompletedChunkReader reader;

  public:
    explicit CommittedLedgerPrefixReader(
      LedgerFile::CompletedChunkReader&& reader_) :
      reader(std::move(reader_))
    {}

    [[nodiscard]] size_t size() const override
    {
      return reader.size();
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> read(
      size_t start, size_t end) const override
    {
      return reader.read(start, end);
    }
  };

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

    [[nodiscard]] std::optional<ccf::ledger::CommittedLedgerPrefixRange>
    committed_ledger_prefix_range_with_idx(size_t idx) override
    {
      return ledger.committed_ledger_prefix_range_with_idx(idx);
    }

    [[nodiscard]] std::unique_ptr<ccf::AbstractCommittedLedgerPrefixReader>
    open_committed_ledger_prefix(size_t from, size_t to) override
    {
      auto reader = ledger.open_committed_ledger_prefix(from, to);
      if (!reader.has_value())
      {
        return nullptr;
      }

      return std::make_unique<CommittedLedgerPrefixReader>(
        std::move(reader.value()));
    }

    [[nodiscard]] size_t get_init_idx() override
    {
      return ledger.get_init_idx();
    }
  };
}
