// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "ccf/tx_id.h"

#include <memory>

namespace ccf::kv
{
  class ReadOnlyStore
  {
  public:
    virtual ~ReadOnlyStore() = default;

    virtual ccf::TxID current_txid() = 0;
    virtual ccf::kv::ReadOnlyTx create_read_only_tx() = 0;
    virtual std::unique_ptr<ccf::kv::ReadOnlyTx> create_read_only_tx_ptr() = 0;
    virtual ccf::kv::TxDiff create_tx_diff() = 0;
  };

  using ReadOnlyStorePtr = std::shared_ptr<ReadOnlyStore>;
}