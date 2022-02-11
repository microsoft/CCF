// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "indexing/transaction_fetcher_interface.h"
#include "node/historical_queries.h"

namespace ccf::indexing
{
  class HistoricalTransactionFetcher : public TransactionFetcher
  {
  private:
    std::shared_ptr<ccf::historical::StateCacheImpl> historical_cache;

  public:
    HistoricalTransactionFetcher(
      const std::shared_ptr<ccf::historical::StateCacheImpl>& sc) :
      historical_cache(sc)
    {}

    StorePtr deserialise_transaction(
      ccf::SeqNo seqno, const uint8_t* data, size_t size) override
    {
      kv::ApplyResult result;
      ccf::ClaimsDigest claims_digest;
      bool has_commit_evidence;
      auto store = historical_cache->deserialise_ledger_entry(
        seqno, data, size, result, claims_digest, has_commit_evidence);
      if (store != nullptr && result != kv::ApplyResult::FAIL)
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
      const ccf::historical::CompoundHandle handle{
        historical::RequestNamespace::System, 0};
      ccf::historical::SeqNoCollection historical_seqnos(
        seqnos.begin(), seqnos.end());
      auto stores = historical_cache->get_stores_for(handle, historical_seqnos);
      if (!stores.empty())
      {
        historical_cache->drop_cached_states(handle);
      }
      return stores;
    }
  };
}
