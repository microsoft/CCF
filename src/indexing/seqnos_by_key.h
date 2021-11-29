// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "indexing/indexing_types.h"
#include "indexing/strategy.h"

#include <memory>
#include <string>

namespace ccf::indexing::strategies
{
  template <typename M>
  class SeqnosByKey : public Strategy
  {
  private:
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    // This entire structure should be shardable, so we can dump parts of it to
    // disk!
    std::unordered_map<kv::untyped::SerialisedEntry, SeqNoCollection>
      seqnos_by_key;

    M map;

  public:
    SeqnosByKey(const M& m) :
      Strategy(fmt::format("SeqnosByKey for {}", m.get_name())),
      map(m)
    {}

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const StorePtr& store) override
    {
      // NB: Don't use M, instead get an untyped view over the map with the same
      // name. This saves deserialisation here, where we work with the raw key.
      auto tx = store->create_tx();
      auto handle = tx.ro<kv::untyped::Map>(map.get_name());
      handle->foreach(
        [this, seqno = tx_id.seqno](const auto& k, const auto& v) {
          seqnos_by_key[k].insert(seqno);
          return true;
        });
    }

    SeqNoCollection get_write_txs(const typename M::Key& key)
    {
      const auto serialised_key = M::KeySerialiser::to_serialised(key);
      const auto it = seqnos_by_key.find(serialised_key);
      if (it != seqnos_by_key.end())
      {
        return it->second;
      }

      return {};
    }
  };
}