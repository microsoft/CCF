// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "ccf/tx_id.h"

#include <memory>

namespace kv
{
  class ReadOnlyStore
  {
  public:
    virtual ~ReadOnlyStore() = default;

    virtual ccf::TxID get_txid() = 0;
    virtual kv::ReadOnlyTx create_read_only_tx() = 0;
    virtual kv::TxDiff create_tx_diff() = 0;
  };

  using ReadOnlyStorePtr = std::shared_ptr<ReadOnlyStore>;
}