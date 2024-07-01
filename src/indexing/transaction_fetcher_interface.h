// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/seq_no_collection.h"
#include "ccf/tx_id.h"

namespace ccf::indexing
{
  class TransactionFetcher
  {
  public:
    virtual ~TransactionFetcher() = default;

    virtual ccf::kv::ReadOnlyStorePtr deserialise_transaction(
      ccf::SeqNo seqno, const uint8_t* data, size_t size) = 0;

    virtual std::vector<ccf::kv::ReadOnlyStorePtr> fetch_transactions(
      const SeqNoCollection& seqnos) = 0;
  };
}
