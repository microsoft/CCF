// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <filesystem>
#include <optional>

namespace ccf
{
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
  };
}