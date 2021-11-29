// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "indexing/transaction_fetcher_interface.h"
#include "node/historical_queries.h"

namespace ccf::indexing
{
  class HistoricalTransactionFetcher : public TransactionFetcher
  {
  private:
    ccf::historical::StateCache& state_cache;

  public:
    HistoricalTransactionFetcher(ccf::historical::StateCache& sc) :
      state_cache(sc)
    {}

    StorePtr deserialise_transaction(
      ccf::SeqNo seqno, const uint8_t* data, size_t size) override
    {
      kv::ApplyResult result;
      auto store =
        state_cache.deserialise_ledger_entry(seqno, data, size, result);
      if (store && result != kv::ApplyResult::FAIL)
      {
        return store;
      }
      else
      {
        LOG_FAIL_FMT("Unable to deserialise transaction at {}", seqno);
      }

      return nullptr;
    }

    std::vector<StorePtr> fetch_transactions(
      const SeqNoCollection& seqnos) override
    {
      // TODO: Dedicated handle?
      LOG_INFO_FMT("Fetching {} seqnos?", seqnos.size());
      return state_cache.get_stores_for(0, seqnos);
    }
  };
}
