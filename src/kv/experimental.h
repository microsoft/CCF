// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/hash.h"
#include "kv_types.h"
#include "map.h"
#include "tx_view.h"

#include <vector>

namespace kv
{
  namespace experimental
  {
    using SerialisedRep = std::vector<uint8_t>;

    template <typename H>
    using UntypedMap = kv::Map<SerialisedRep, SerialisedRep, H>;

    template <typename H>
    using UntypedView = kv::TxView<SerialisedRep, SerialisedRep, H>;

    template <typename K, typename V, typename H>
    class TxView
    {
    protected:
      using UV = UntypedView<H>;

      std::unique_ptr<UV> untyped_view;

      SerialisedRep from_k(const K& key)
      {
        return {};
      }

      K to_k(const SerialisedRep& rep)
      {
        return {};
      }

      SerialisedRep from_v(const V& value)
      {
        return {};
      }

      V to_v(const SerialisedRep& rep)
      {
        return {};
      }

    public:
      TxView(UV* uv) : untyped_view(uv) {}

      std::optional<V> get(const K& key)
      {
        const auto k_rep = from_k(key);
        const auto opt_v_rep = untyped_view.get(k_rep);

        if (opt_v_rep.has_value())
        {
          return to_v(*opt_v_rep);
        }

        return std::nullopt;
      }

      std::optional<V> get_globally_committed(const K& key)
      {
        const auto k_rep = from_k(key);
        const auto opt_v_rep = untyped_view->get_globally_committed(k_rep);

        if (opt_v_rep.has_value())
        {
          return to_v(*opt_v_rep);
        }

        return std::nullopt;
      }

      bool put(const K& key, const V& value)
      {
        const auto k_rep = from_k(key);
        const auto v_rep = from_v(value);

        return untyped_view->put(k_rep, v_rep);
      }

      bool remove(const K& key)
      {
        const auto k_rep = from_k(key);

        return untyped_view->put(k_rep);
      }

      template <class F>
      bool foreach(F&& f)
      {
        auto g = [&](const SerialisedRep& k_rep, const SerialisedRep& v_rep) {
          return f(to_k(k_rep), to_v(v_rep));
        };
        return untyped_view->foreach(g);
      }
    };

    template <class K, class V, class H>
    class ConcreteTxView : public TxView<K, V, H>, public AbstractTxView
    {
    protected:
      using Base = TxView<K, V, H>;

    public:
      using Base::Base;
    };

    template <typename K, typename V, typename H = std::hash<SerialisedRep>>
    class Map : public UntypedMap<H>
    {
    protected:
      using Base = UntypedMap<H>;

    public:
      using Base::Base;

      AbstractTxView* create_view(Version version) override
      {
        return new kv::experimental::ConcreteTxView<K, V, H>(
          Base::create_view_internal(version));
      }
    };
  }
}