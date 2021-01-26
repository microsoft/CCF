// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/untyped_map.h"
#include "kv/untyped_map_handle.h"
#include "kv_types.h"

namespace kv
{
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class ReadableMapHandle
  {
  protected:
    kv::untyped::MapHandle& read_handle;

  public:
    using KeyType = K;
    using ValueType = V;

    ReadableMapHandle(kv::untyped::MapHandle& uh) : read_handle(uh) {}

    std::optional<V> get(const K& key)
    {
      const auto opt_v_rep = read_handle.get(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    std::optional<V> get_globally_committed(const K& key)
    {
      const auto opt_v_rep =
        read_handle.get_globally_committed(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    bool has(const K& key)
    {
      return read_handle.has(KSerialiser::to_serialised(key));
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
      read_handle.foreach(g);
    }
  };

  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class WriteableMapHandle
  {
  protected:
    kv::untyped::MapHandle& write_handle;

  public:
    WriteableMapHandle(kv::untyped::MapHandle& uh) : write_handle(uh) {}

    bool put(const K& key, const V& value)
    {
      return write_handle.put(
        KSerialiser::to_serialised(key), VSerialiser::to_serialised(value));
    }

    bool remove(const K& key)
    {
      return write_handle.remove(KSerialiser::to_serialised(key));
    }
  };

  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class MapHandle : public AbstractMapHandle,
                    public ReadableMapHandle<K, V, KSerialiser, VSerialiser>,
                    public WriteableMapHandle<K, V, KSerialiser, VSerialiser>
  {
  protected:
    kv::untyped::MapHandle untyped_handle;

    using ReadableBase = ReadableMapHandle<K, V, KSerialiser, VSerialiser>;
    using WriteableBase = WriteableMapHandle<K, V, KSerialiser, VSerialiser>;

  public:
    MapHandle(kv::untyped::ChangeSet& changes) :
      ReadableBase(untyped_handle),
      WriteableBase(untyped_handle),
      untyped_handle(changes)
    {}
  };
}