// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "indexing/strategy.h"

#include <memory>
#include <string>

namespace indexing
{
  // This is responsible for managing a collection of strategies, and ensuring
  // each has been given every transaction up to the commit point, in-order. On
  // the hot path, it receives uncommitted entries and commit progress from
  // consensus. However, it also must fetch historical entries (to populate
  // entries for strategies installed after construction, or to populate entries
  // when this node was initialised via snapshot rather than consensus)
  class Indexer
  {
  private:
    std::map<std::string, StrategyPtr> strategies;

    using PendingTx = std::pair<ccf::TxID, std::vector<uint8_t>>;
    std::vector<PendingTx> uncommitted_entries;

    ccf::TxID committed;

    static bool tx_id_less(const ccf::TxID& a, const ccf::TxID& b)
    {
      // NB: This will return true for 2.10 < 4.5, which isn't necessarily
      // what's wanted in all comparisons (that's why this isn't implemented for
      // ccf::TxID directly). But it's fine for everywhere we use it here, since
      // we assume we only see a node's transitions in-order.
      return a.view < b.view || a.seqno < b.seqno;
    }

    static bool uncommitted_entries_cmp(const ccf::TxID& a, const PendingTx& b)
    {
      return tx_id_less(a, b.first);
    }

  public:
    void install_strategy(StrategyPtr&& strategy)
    {
      if (strategy == nullptr)
      {
        throw std::logic_error("Tried to install null strategy");
      }

      auto it = strategies.find(strategy->get_name());
      if (it != strategies.end())
      {
        throw std::logic_error(fmt::format(
          "Strategy named {} already exists", strategy->get_name()));
      }

      strategies.emplace_hint(it, strategy->get_name(), std::move(strategy));
    }

    template <typename T>
    T* get_strategy(const std::string& name)
    {
      auto it = strategies.find(name);
      if (it != strategies.end())
      {
        auto t = dynamic_cast<T*>(it->second.get());
        return t;
      }

      return nullptr;
    }

    void tick()
    {
      // TODO: Work out which strategies haven't been given the commit point
      // TODO: Request some prefix of the missing entries (not all of them at
      // once, cap the amount of work done by the number of entries fetched)

      // TODO: When we receive the responses, do we process them inline
      // (blocking the ringbuffer reading thread) or store them until this tick
      // (needing an in-enclave copy)?
    }

    // TODO: So _maybe_ we can be given these before they leave the enclave, and
    // just process them on tick() once commit has passed them. But that's risky
    // memory pressure! Should we instead begin fetching a range we think we can
    // hold, after commit, async?
    void append_entry(const ccf::TxID& tx_id, const uint8_t* data, size_t size)
    {
      if (tx_id_less(tx_id, committed))
      {
        throw std::logic_error(fmt::format(
          "Appending entry out-of-order. Committed to {}, trying to append {}",
          committed.to_str(),
          tx_id.to_str()));
      }

      if (!uncommitted_entries.empty())
      {
        const auto& [back_id, _] = uncommitted_entries.back();
        if (tx_id_less(tx_id, back_id))
        {
          throw std::logic_error(fmt::format(
            "Appending entry out-of-order. Last entry is {}, trying to append "
            "{}",
            back_id.to_str(),
            tx_id.to_str()));
        }
      }

      uncommitted_entries.emplace_back(
        std::make_pair(tx_id, std::vector<uint8_t>{data, data + size}));
    }

    void rollback(const ccf::TxID& tx_id)
    {
      auto it = std::upper_bound(
        uncommitted_entries.begin(),
        uncommitted_entries.end(),
        tx_id,
        [](const ccf::TxID& a, const PendingTx& b) {
          return tx_id_less(a, b.first);
        });
      uncommitted_entries.erase(it, uncommitted_entries.end());
    }

    void commit(const ccf::TxID& tx_id)
    {
      if (tx_id_less(tx_id, committed))
      {
        throw std::logic_error(fmt::format(
          "Committing out-of-order. Committed to {}, trying to commit {}",
          committed.to_str(),
          tx_id.to_str()));
      }

      auto end_it = std::lower_bound(
        uncommitted_entries.begin(),
        uncommitted_entries.end(),
        tx_id,
        [](const PendingTx& a, const ccf::TxID& b) {
          return tx_id_less(a.first, b);
        });

      for (auto it = uncommitted_entries.begin(); it != end_it; ++it)
      {
        const auto& [id, entry] = *it;
        for (auto& [_, strategy] : strategies)
        {
          strategy->append_committed_transaction(
            id, entry.data(), entry.size());
        }
      }
      uncommitted_entries.erase(uncommitted_entries.begin(), end_it);

      committed = tx_id;
    }
  };
}