// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "ccf/tx_id.h"

#include <memory>

namespace kv
{
  struct TxID;

  class ReadOnlyStore
  {
  public:
    virtual ~ReadOnlyStore();

    // TODO: Should be a ccf::TxID?
    virtual kv::TxID current_txid() = 0;
    virtual kv::ReadOnlyTx create_read_only_tx() = 0;
  };

  using ReadOnlyStorePtr = std::shared_ptr<ReadOnlyStore>;
}