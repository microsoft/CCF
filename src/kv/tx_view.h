// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/untyped/tx_view.h"

#include "kv/untyped/map.h"
#include "kv_types.h"

namespace kv
{
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class TxView : public kv::untyped::TxViewCommitter
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
      kv::untyped::TxViewCommitter(
        m, rollbacks, current_state, committed_state, v),
      untyped_view(kv::untyped::TxViewCommitter::change_set)
    {}

    std::optional<V> get(const K& key)
    {
      const auto k_rep = KSerialiser::to_serialised(key);
      const auto opt_v_rep = untyped_view.get(k_rep);

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    std::optional<V> get_globally_committed(const K& key)
    {
      const auto k_rep = KSerialiser::to_serialised(key);
      const auto opt_v_rep = untyped_view.get_globally_committed(k_rep);

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    bool put(const K& key, const V& value)
    {
      const auto k_rep = KSerialiser::to_serialised(key);
      const auto v_rep = VSerialiser::to_serialised(value);

      return untyped_view.put(k_rep, v_rep);
    }

    bool remove(const K& key)
    {
      const auto k_rep = KSerialiser::to_serialised(key);

      return untyped_view.remove(k_rep);
    }

    template <class F>
    void foreach(F&& f)
    {
      auto g = [&](const SerialisedEntry& k_rep, const SerialisedEntry& v_rep) {
        return f(
          KSerialiser::from_serialised(k_rep),
          VSerialiser::from_serialised(v_rep));
      };
      untyped_view.foreach(g);
    }
  };
}