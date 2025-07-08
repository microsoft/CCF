// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/version.h"
#include "kv/ledger_chunker_interface.h"

#include <cstdint>
#include <limits>
#include <map>
#include <numeric>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::kv
{
  struct LedgerChunker : public ILedgerChunker
  {
    // protected: TODO
  public:
    const size_t chunk_threshold;

    std::optional<Version> forced_chunk_version = std::nullopt;
    std::map<Version, size_t> transaction_sizes = {};

    Version current_tx_version = 0;

    size_t get_unchunked_size() const
    {
      return std::accumulate(
        transaction_sizes.begin(),
        transaction_sizes.end(),
        0,
        [](size_t n, const auto& p) { return n + p.second; });
    }

  public:
    static constexpr size_t max_chunk_threshold_size =
      std::numeric_limits<uint32_t>::max(); // 4GB

    LedgerChunker(size_t threshold = max_chunk_threshold_size) :
      chunk_threshold(threshold)
    {
      if (threshold == 0 || threshold > max_chunk_threshold_size)
      {
        throw std::logic_error(fmt::format(
          "Error: Ledger chunk threshold ({}) must be between 1-{}",
          threshold,
          max_chunk_threshold_size));
      }
    }

    void append_entry_size(size_t n) override
    {
      transaction_sizes[++current_tx_version] = n;
    }

    void force_end_of_chunk(Version v) override
    {
      if (forced_chunk_version.value_or(0) < v)
      {
        forced_chunk_version = v;
      }
    }

    bool is_chunk_end_requested(Version v) override
    {
      if (forced_chunk_version.has_value() && forced_chunk_version.value() <= v)
      {
        return true;
      }

      return get_unchunked_size() >= chunk_threshold;
    }

    void rolled_back_to(Version v) override
    {
      current_tx_version = v;

      transaction_sizes.erase(
        transaction_sizes.upper_bound(v), transaction_sizes.end());

      if (forced_chunk_version.has_value() && forced_chunk_version.value() > v)
      {
        forced_chunk_version.reset();
      }
    }

    void produced_chunk_at(Version v) override
    {
      transaction_sizes.erase(
        transaction_sizes.begin(), transaction_sizes.upper_bound(v));

      if (forced_chunk_version.has_value() && forced_chunk_version.value() <= v)
      {
        forced_chunk_version.reset();
      }
    }
  };
}
