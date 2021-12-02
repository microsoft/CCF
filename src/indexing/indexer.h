// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "indexing/strategy.h"
#include "indexing/transaction_fetcher_interface.h"

#include <memory>
#include <string>

namespace ccf::indexing
{
  // This is responsible for managing a collection of strategies, and ensuring
  // each has been given every transaction up to the commit point, in-order. It
  // is informed of commit progress by the consensus, and then fetches
  // transactions through the historical query system (to populate entries for
  // strategies installed after construction, or to populate entries when this
  // node was initialised via snapshot rather than consensus).
  class Indexer
  {
  public:
    static constexpr size_t MAX_REQUESTABLE = 1000;

  private:
    TransactionFetcher& transaction_fetcher;

    // Store the highest TxID that each strategy has been given, and assume it
    // doesn't need to be given again later.
    using StrategyContext = std::pair<ccf::TxID, StrategyPtr>;
    std::map<std::string, StrategyContext> strategies;

    using PendingTx = std::pair<ccf::TxID, std::vector<uint8_t>>;
    std::vector<PendingTx> uncommitted_entries;

    ccf::TxID committed = {};

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
    Indexer(TransactionFetcher& tf) : transaction_fetcher(tf) {}

    std::string install_strategy(StrategyPtr&& strategy)
    {
      if (strategy == nullptr)
      {
        throw std::logic_error("Tried to install null strategy");
      }

      const auto name = strategy->get_name();

      auto it = strategies.find(name);
      if (it != strategies.end())
      {
        throw std::logic_error(
          fmt::format("Strategy named {} already exists", name));
      }

      strategies.emplace_hint(
        it, name, std::make_pair(ccf::TxID{}, std::move(strategy)));

      return name;
    }

    template <typename T>
    T* get_strategy(const std::string& name)
    {
      auto it = strategies.find(name);
      if (it != strategies.end())
      {
        auto t = dynamic_cast<T*>(it->second.second.get());
        return t;
      }

      return nullptr;
    }

    // Returns true if it looks like there's still a gap to fill. Useful for
    // testing
    bool tick()
    {
      std::optional<ccf::TxID> min_provided = std::nullopt;
      for (auto& [name, ctx] : strategies)
      {
        auto& [last_provided, strategy] = ctx;

        strategy->tick();

        if (
          !min_provided.has_value() || tx_id_less(last_provided, *min_provided))
        {
          min_provided = last_provided;
        }
      }

      if (min_provided.has_value())
      {
        if (tx_id_less(*min_provided, committed))
        {
          // Request a prefix of the missing entries. Cap the requested range,
          // so we don't overload the node with a huge historical request
          const auto first_requested = min_provided->seqno + 1;
          auto additional =
            std::min(MAX_REQUESTABLE, committed.seqno - first_requested);

          SeqNoCollection seqnos(first_requested, additional);

          auto stores = transaction_fetcher.fetch_transactions(seqnos);
          for (auto& store : stores)
          {
            const auto tx_id_ = store->current_txid();
            const ccf::TxID tx_id{tx_id_.term, tx_id_.version};

            for (auto& [name, ctx] : strategies)
            {
              auto& [last_provided, strategy] = ctx;
              if (tx_id.seqno == last_provided.seqno + 1)
              {
                strategy->handle_committed_transaction(tx_id, store);
                last_provided = tx_id;
              }
            }
          }

          return true;
        }
      }

      return false;
    }

    // TODO: So _maybe_ we can be given these before they leave the enclave, and
    // just process them on tick() once commit has passed them. But that's risky
    // memory pressure!
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

      auto end_it = std::upper_bound(
        uncommitted_entries.begin(),
        uncommitted_entries.end(),
        tx_id,
        [](const ccf::TxID& a, const PendingTx& b) {
          return tx_id_less(a, b.first);
        });

      for (auto it = uncommitted_entries.begin(); it != end_it; ++it)
      {
        const auto& [id, entry] = *it;

        auto store_ptr = transaction_fetcher.deserialise_transaction(
          id.seqno, entry.data(), entry.size());

        if (store_ptr != nullptr)
        {
          for (auto& [name, ctxt] : strategies)
          {
            auto& [seen_so_far, strategy] = ctxt;
            // Only pass if this is the next seqno this index is seeking
            if (seen_so_far.seqno + 1 == id.seqno)
            {
              strategy->handle_committed_transaction(id, store_ptr);
              ctxt.first = id;
            }
          }
        }
      }

      uncommitted_entries.erase(uncommitted_entries.begin(), end_it);

      committed = tx_id;
    }
  };
}