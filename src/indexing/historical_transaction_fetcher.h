// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "indexing/transaction_fetcher_interface.h"
#include "node/historical_queries.h"

namespace ccf::indexing
{
  class HistoricalTransactionFetcher : public TransactionFetcher
  {
  public:
    StorePtr deserialise_transaction(
      ccf::SeqNo seqno, const uint8_t* data, size_t size) override
    {
      return nullptr;
    }

    std::vector<StorePtr> fetch_transactions(
      const SeqNoCollection& seqnos) override
    {
      return {};
    }
  };
}
