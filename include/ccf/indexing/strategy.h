// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "kv/store.h"

#include <memory>
#include <string>

namespace ccf::indexing
{
  class Strategy
  {
    const std::string name;

  public:
    Strategy(const std::string& name) : name(name) {}
    virtual ~Strategy() = default;

    std::string get_name() const
    {
      return name;
    }

    // Receives every committed transaction, in-order
    virtual void handle_committed_transaction(
      const ccf::TxID& tx_id, const std::shared_ptr<kv::Store>& store) = 0;

    virtual void tick() {}

    // Returns highest tx ID for which this index should be populated, or
    // nullopt if it wants all Txs. Allows indexes to be populatep
    // lazily on-demand.
    virtual std::optional<ccf::TxID> highest_requested()
    {
      return std::nullopt;
    }
  };

  using StrategyPtr = std::shared_ptr<Strategy>;

  template <typename Base>
  class LazyStrategy : public Base
  {
  protected:
    ccf::TxID requested_txid = {};

  public:
    using Base::Base;

    virtual std::optional<ccf::TxID> highest_requested()
    {
      return requested_txid;
    }

    void extend_index_to(ccf::TxID to_txid)
    {
      if (to_txid.seqno > requested_txid.seqno)
      {
        requested_txid = to_txid;
      }
    }
  };
}