// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/indexer_interface.h"
#include "ds/logger.h"
#include "indexing/transaction_fetcher_interface.h"

#include <memory>
#include <string>

namespace ccf::indexing
{
  // This is responsible for managing a collection of strategies, and ensuring
  // each has been given every transaction up to the commit point, in-order. It
  // is informed of new entries commit progress by the consensus, and if it sees
  // any holes (for instance because a strategy is installed after some
  // transactions are run, or because this node started from existing state and
  // not all entries were received through consensus) then it fetches them and
  // passes them onto each strategy.
  class Indexer : public IndexingStrategies
  {
  public:
    static constexpr size_t MAX_REQUESTABLE = 100;

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

      std::optional<ccf::TxID> min_provided = std::nullopt;
      for (auto& [strategy, last_provided] : strategies)
      {
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
          auto additional = std::min(
            MAX_REQUESTABLE - uncommitted_entries.size(),
            committed.seqno - first_requested);

          SeqNoCollection seqnos(first_requested, additional);

          auto stores = transaction_fetcher->fetch_transactions(seqnos);
          for (auto& store : stores)
          {
            const auto tx_id_ = store->current_txid();
            const ccf::TxID tx_id{tx_id_.term, tx_id_.version};

            for (auto& [strategy, last_provided] : strategies)
            {
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
  };
}