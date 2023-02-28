// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/indexing/indexer_interface.h"
#include "indexing/transaction_fetcher_interface.h"
#include "kv/kv_types.h"
#include "kv/store.h"

#include <memory>
#include <string>

namespace ccf::indexing
{
  // This is responsible for managing a collection of strategies, and ensuring
  // each has been given every transaction up to the commit point, in-order.
  class Indexer : public IndexingStrategies
  {
  public:
    static constexpr size_t MAX_REQUESTABLE = 500;

  protected:
    std::shared_ptr<TransactionFetcher> transaction_fetcher;

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

    void update_commit(const ccf::TxID& tx_id)
    {
      if (tx_id_less(tx_id, committed))
      {
        throw std::logic_error(fmt::format(
          "Committing out-of-order. Committed to {}, trying to commit {}",
          committed.to_str(),
          tx_id.to_str()));
      }

      committed = tx_id;
    }

  public:
    Indexer(const std::shared_ptr<TransactionFetcher>& tf) :
      transaction_fetcher(tf)
    {}

    // Returns true if it looks like there's still a gap to fill. Useful for
    // testing
    bool update_strategies(
      std::chrono::milliseconds elapsed, const ccf::TxID& newly_committed)
    {
      update_commit(newly_committed);

      std::optional<ccf::SeqNo> min_requested = std::nullopt;
      for (auto& strategy : strategies)
      {
        strategy->tick();

        const auto next_requested = strategy->next_requested();
        if (!next_requested.has_value())
        {
          // If this strategy has an upper-bound on Txs it cares about, and
          // we've already provided that, don't consider advancing it any
          // further
          continue;
        }

        if (!min_requested.has_value() || *next_requested < *min_requested)
        {
          min_requested = next_requested;
        }
      }

      if (min_requested.has_value())
      {
        if (*min_requested <= committed.seqno)
        {
          // Request a prefix of the missing entries. Cap the requested range,
          // so we don't overload the node with a huge historical request
          const auto first_requested = *min_requested;
          auto additional = std::min(
            MAX_REQUESTABLE - uncommitted_entries.size(),
            committed.seqno - first_requested);

          SeqNoCollection seqnos;
          for (auto i = first_requested; i <= first_requested + additional; ++i)
          {
            seqnos.insert(i);
          }

          auto stores = transaction_fetcher->fetch_transactions(seqnos);
          for (auto& store : stores)
          {
            const ccf::TxID tx_id = store->get_txid();

            for (auto& strategy : strategies)
            {
              const auto next_requested = strategy->next_requested();
              if (
                next_requested.has_value() && (tx_id.seqno == *next_requested))
              {
                strategy->handle_committed_transaction(tx_id, store);
              }
            }
          }

          return true;
        }
      }

      return false;
    }
  };
}