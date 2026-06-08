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
  protected:
    const size_t chunk_threshold;
    Version current_tx_version;

    std::map<Version, size_t> transaction_sizes = {};
    std::set<Version> chunk_ends = {};
    std::set<Version> forced_chunk_versions = {};

    size_t get_unchunked_size(Version up_to) const
    {
      auto begin = transaction_sizes.cbegin();
      auto end = transaction_sizes.upper_bound(up_to);

      auto chunk_before = chunk_ends.lower_bound(up_to);
      if (chunk_before != chunk_ends.begin())
      {
        std::advance(chunk_before, -1);
        begin = transaction_sizes.upper_bound(*chunk_before);
      }

      return std::accumulate(
        begin, end, 0, [](size_t n, const auto& p) { return n + p.second; });
    }

  public:
    static constexpr size_t max_chunk_threshold_size =
      std::numeric_limits<uint32_t>::max(); // 4GB

    LedgerChunker(
      size_t threshold = max_chunk_threshold_size, Version start_from = 0) :
      chunk_threshold(threshold),
      current_tx_version(start_from)
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
      forced_chunk_versions.insert(v);
    }

    bool is_chunk_end_requested(Version v) override
    {
      if (!forced_chunk_versions.empty())
      {
        // There is an outstanding forced-chunk request for this if there is a
        // forced-chunk request at f <= v, and no chunk_end >= f

        // upper_bound > v
        auto forced_it = forced_chunk_versions.upper_bound(v);
        if (forced_it != forced_chunk_versions.begin())
        {
          // There is some f before forced_it, which is <= v
          std::advance(forced_it, -1);
          Version f = *forced_it;

          const auto ender_it = chunk_ends.lower_bound(f);
          if (ender_it == chunk_ends.end())
          {
            return true;
          }
        }
      }

      return get_unchunked_size(v) >= chunk_threshold;
    }

    void rolled_back_to(Version v) override
    {
      current_tx_version = v;

      transaction_sizes.erase(
        transaction_sizes.upper_bound(v), transaction_sizes.end());
      chunk_ends.erase(chunk_ends.upper_bound(v), chunk_ends.end());
      forced_chunk_versions.erase(
        forced_chunk_versions.upper_bound(v), forced_chunk_versions.end());
    }

    void compacted_to(Version v) override
    {
      Version compactable_v;

      auto compactable_it = chunk_ends.lower_bound(v);
      if (compactable_it != chunk_ends.begin())
      {
        std::advance(compactable_it, -1);
        compactable_v = *compactable_it;
      }
      else
      {
        compactable_v = 0;
      }

      transaction_sizes.erase(
        transaction_sizes.begin(),
        transaction_sizes.upper_bound(compactable_v));
      chunk_ends.erase(
        chunk_ends.begin(), chunk_ends.upper_bound(compactable_v));
      forced_chunk_versions.erase(
        forced_chunk_versions.begin(),
        forced_chunk_versions.upper_bound(compactable_v));
    }

    void produced_chunk_at(Version v) override
    {
      chunk_ends.insert(v);
    }
  };
}
