// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "indexing/indexing_types.h"

namespace ccf::indexing
{
  class TransactionFetcher
  {
  public:
    virtual ~TransactionFetcher() = default;

    virtual StorePtr deserialise_transaction(
      ccf::SeqNo seqno, const uint8_t* data, size_t size) = 0;

    virtual std::vector<StorePtr> fetch_transactions(
      const SeqNoCollection& seqnos) = 0;
  };
}
