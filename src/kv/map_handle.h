// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/untyped_map.h"
#include "kv/untyped_map_handle.h"
#include "kv_types.h"

namespace kv
{
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class ReadOnlyMapHandle : public AbstractMapHandle
  {
  protected:
    kv::untyped::MapHandle untyped_handle;

  public:
    using KeyType = K;
    using ValueType = V;

    ReadOnlyMapHandle(kv::untyped::ChangeSet& changes) : untyped_handle(changes)
    {}

    std::optional<V> get(const K& key)
    {
      const auto opt_v_rep =
        untyped_handle.get(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    std::optional<V> get_globally_committed(const K& key)
    {
      const auto opt_v_rep =
        untyped_handle.get_globally_committed(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    bool has(const K& key)
    {
      return untyped_handle.has(KSerialiser::to_serialised(key));
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
      untyped_handle.foreach(g);
    }
  };

  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class MapHandle : public ReadOnlyMapHandle<K, V, KSerialiser, VSerialiser>
  {
  protected:
    using ReadOnlyBase = ReadOnlyMapHandle<K, V, KSerialiser, VSerialiser>;

  public:
    using ReadOnlyBase::ReadOnlyBase;

    bool put(const K& key, const V& value)
    {
      return ReadOnlyBase::untyped_handle.put(
        KSerialiser::to_serialised(key), VSerialiser::to_serialised(value));
    }

    bool remove(const K& key)
    {
      return ReadOnlyBase::untyped_handle.remove(
        KSerialiser::to_serialised(key));
    }
  };
}