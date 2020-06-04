// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/untyped_map.h"
#include "kv/untyped_tx_view.h"
#include "kv_types.h"

namespace kv
{
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class TxView : public kv::untyped::Map::TxViewCommitter
  {
  protected:
    kv::untyped::TxView untyped_view;

  public:
    using KeyType = K;
    using ValueType = V;

    TxView(
      kv::untyped::Map& m,
      size_t rollbacks,
      kv::untyped::State& current_state,
      kv::untyped::State& committed_state,
      Version v) :
      kv::untyped::Map::TxViewCommitter(
        m, rollbacks, current_state, committed_state, v),
      untyped_view(kv::untyped::Map::TxViewCommitter::change_set)
    {}

    std::optional<V> get(const K& key)
    {
      const auto opt_v_rep = untyped_view.get(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    std::optional<V> get_globally_committed(const K& key)
    {
      const auto opt_v_rep = untyped_view.get_globally_committed(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    bool put(const K& key, const V& value)
    {
      return untyped_view.put(KSerialiser::to_serialised(key), VSerialiser::to_serialised(value));
    }

    bool remove(const K& key)
    {
      return untyped_view.remove(KSerialiser::to_serialised(key));
    }

    template <class F>
    void foreach(F&& f)
    {
      auto g = [&](
                 const kv::serialisers::SerialisedEntry& k_rep,
                 const kv::serialisers::SerialisedEntry& v_rep) {
        return f(
          KSerialiser::from_serialised(k_rep),
          VSerialiser::from_serialised(v_rep));
      };
      untyped_view.foreach(g);
    }
  };
}