// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "consensus/ledger_enclave_types.h"

#include <filesystem>
#include <optional>

namespace ccf
{
  class AbstractLedgerSubsystemInterface
    : public AbstractNodeSubSystem,
      public ::consensus::AbstractLedgerWriter,
      public ::consensus::AbstractLedgerReader
  {
  public:
    ~AbstractLedgerSubsystemInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "LedgerInterface";
    }

    virtual std::optional<std::filesystem::path> committed_ledger_path_with_idx(
      size_t idx) = 0;

    virtual size_t get_init_idx() = 0;

    virtual void shutdown() = 0;
  };
}