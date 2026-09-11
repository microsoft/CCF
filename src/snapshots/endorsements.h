// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace snapshots
{
  // Match the limits used for ledger-backed recovery snapshot endorsements.
  static constexpr size_t MAX_ENDORSEMENTS_COUNT = 64;
  static constexpr size_t MAX_ENDORSEMENT_SIZE = size_t{1024} * 1024;
  static constexpr size_t MAX_ENDORSEMENTS_SIZE = size_t{4} * 1024 * 1024;
  static constexpr size_t MAX_ENDORSEMENTS_RESPONSE_SIZE =
    2 * MAX_ENDORSEMENTS_SIZE;

  inline void check_endorsements_size(
    const std::vector<std::vector<uint8_t>>& endorsements)
  {
    if (endorsements.size() > MAX_ENDORSEMENTS_COUNT)
    {
      throw std::logic_error("Snapshot endorsement chain has too many links");
    }
    size_t total = 0;
    for (const auto& endorsement : endorsements)
    {
      if (
        endorsement.empty() || endorsement.size() > MAX_ENDORSEMENT_SIZE ||
        endorsement.size() > MAX_ENDORSEMENTS_SIZE - total)
      {
        throw std::logic_error(
          "Snapshot endorsement chain exceeds size limits");
      }
      total += endorsement.size();
    }
  }
}
