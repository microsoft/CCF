// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/read_only_store.h"
#include "ccf/tx_id.h"

#include <optional>
#include <string>

namespace ccf::indexing
{
  /** The base class for all indexing strategies.
   *
   * Sub-class this and override handle_committed_transaction to implement your
   * own indexing strategy. Create an instance of this on each node, and then
   * install it with context.get_indexing_strategies().install_strategy(). It
   * will then be given each committed transaction shortly after commit. You
   * should build some aggregate/summary from these transactions, and return
   * that to endpoint handlers in an efficient format.
   */
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

    /** Receives every committed transaction, in-order, shortly after commit.
     *
     * The given store contains only the changes that occured in the current
     * transaction.
     */
    virtual void handle_committed_transaction(
      const ccf::TxID& tx_id, const kv::ReadOnlyStorePtr& store) = 0;

    virtual void tick() {}

    /** Returns next tx for which this index should be populated, or
     * nullopt if it wants none. Allows indexes to be populated
     * lazily on-demand, or out-of-order, or reset */
    virtual std::optional<ccf::SeqNo> next_requested() = 0;

    virtual nlohmann::json describe()
    {
      auto j = nlohmann::json::object();
      j["name"] = get_name();

      const auto nr = next_requested();
      if (nr.has_value())
      {
        j["next_requested_seqno"] = *nr;
      }

      return j;
    }
  };

  using StrategyPtr = std::shared_ptr<Strategy>;

  template <typename Base>
  class LazyStrategy : public Base
  {
  protected:
    ccf::SeqNo max_requested_seqno = 0;

  public:
    using Base::Base;

    std::optional<ccf::SeqNo> next_requested() override
    {
      const auto base = Base::next_requested();
      if (base.has_value())
      {
        if (*base <= max_requested_seqno)
        {
          return base;
        }
      }

      return std::nullopt;
    }

    void extend_index_to(ccf::TxID to_txid)
    {
      if (to_txid.seqno > max_requested_seqno)
      {
        max_requested_seqno = to_txid.seqno;
      }
    }
  };
}