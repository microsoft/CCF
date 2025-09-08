// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
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

    ccf::kv::ReadOnlyStorePtr deserialise_transaction(
      ccf::SeqNo seqno, const uint8_t* data, size_t size) override
    {
      ccf::kv::ApplyResult result;
      ccf::ClaimsDigest claims_digest;
      bool has_commit_evidence;
      auto store = historical_cache->deserialise_ledger_entry(
        seqno, data, size, result, claims_digest, has_commit_evidence);
      if (store != nullptr && result != ccf::kv::ApplyResult::FAIL)
      {
        return store;
      }
      else
      {
        LOG_FAIL_FMT("Unable to deserialise transaction at {}", seqno);
      }

      return nullptr;
    }

    std::vector<ccf::kv::ReadOnlyStorePtr> fetch_transactions(
      const SeqNoCollection& seqnos) override
    {
      const ccf::historical::CompoundHandle handle{
        historical::RequestNamespace::System, 0};
      auto stores = historical_cache->get_stores_for(handle, seqnos);
      if (!stores.empty())
      {
        historical_cache->drop_cached_states(handle);
      }
      return stores;
    }
  };
}
