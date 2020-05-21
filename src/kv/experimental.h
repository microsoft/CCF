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

    // TODO: I don't think this needs to be customisable? If the map is storing
    // _your_ types as keys, you might need to tell it how to compare them. But
    // we know how to compare byte-vectors, and this is an internal detail so
    // why would you change it?
    using RepHasher = std::hash<SerialisedRep>;

    using UntypedMap = kv::Map<SerialisedRep, SerialisedRep, RepHasher>;

    using UntypedOperationsView =
      kv::TxView<SerialisedRep, SerialisedRep, RepHasher>;

    using UntypedCommitter =
      kv::TxViewCommitter<SerialisedRep, SerialisedRep, RepHasher>;

    using UntypedState = kv::State<SerialisedRep, SerialisedRep, RepHasher>;

    template <typename K, typename V>
    struct MsgPackSerialiser
    {
    private:
      template <typename T>
      static SerialisedRep from_t(const T& t)
      {
        msgpack::sbuffer sb;
        msgpack::pack(sb, t);
        auto sb_data = reinterpret_cast<const uint8_t*>(sb.data());
        return SerialisedRep(sb_data, sb_data + sb.size());
      }

      template <typename T>
      static T to_t(const SerialisedRep& rep)
      {
        msgpack::object_handle oh = msgpack::unpack(
          reinterpret_cast<const char*>(rep.data()), rep.size());
        auto object = oh.get();
        return object.as<T>();
      }

    public:
      static SerialisedRep from_k(const K& k)
      {
        return from_t<K>(k);
      }

      static K to_k(const SerialisedRep& rep)
      {
        return to_t<K>(rep);
      }

      static SerialisedRep from_v(const V& v)
      {
        return from_t<V>(v);
      }

      static V to_v(const SerialisedRep& rep)
      {
        return to_t<V>(rep);
      }
    };

    template <typename K, typename V, typename S>
    class TxView : public UntypedCommitter
    {
    protected:
      // This _has_ a (non-visible, untyped) view, whereas the standard impl
      // _is_ a typed view
      UntypedOperationsView untyped_view;

    public:
      TxView(
        UntypedMap& m,
        size_t rollbacks,
        UntypedState& current_state,
        UntypedState& committed_state,
        Version v) :
        UntypedCommitter(m, rollbacks, current_state, committed_state, v),
        untyped_view(UntypedCommitter::change_set)
      {}

      std::optional<V> get(const K& key)
      {
        const auto k_rep = S::from_k(key);
        const auto opt_v_rep = untyped_view.get(k_rep);

        if (opt_v_rep.has_value())
        {
          return S::to_v(*opt_v_rep);
        }

        return std::nullopt;
      }

      std::optional<V> get_globally_committed(const K& key)
      {
        const auto k_rep = S::from_k(key);
        const auto opt_v_rep = untyped_view.get_globally_committed(k_rep);

        if (opt_v_rep.has_value())
        {
          return S::to_v(*opt_v_rep);
        }

        return std::nullopt;
      }

      bool put(const K& key, const V& value)
      {
        const auto k_rep = S::from_k(key);
        const auto v_rep = S::from_v(value);

        return untyped_view.put(k_rep, v_rep);
      }

      bool remove(const K& key)
      {
        const auto k_rep = S::from_k(key);

        return untyped_view.remove(k_rep);
      }

      template <class F>
      bool foreach(F&& f)
      {
        auto g = [&](const SerialisedRep& k_rep, const SerialisedRep& v_rep) {
          return f(S::to_k(k_rep), S::to_v(v_rep));
        };
        return untyped_view.foreach(g);
      }
    };

    template <typename K, typename V, typename S = MsgPackSerialiser<K, V>>
    class Map : public UntypedMap
    {
    protected:
      using Base = UntypedMap;

    public:
      using Base::Base;

      using TxView = kv::experimental::TxView<K, V, S>;

      AbstractTxView* create_view(Version version) override
      {
        return Base::template create_view_internal<TxView>(version);
      }
    };
  }
}