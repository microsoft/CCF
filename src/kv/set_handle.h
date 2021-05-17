// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/unit.h"
#include "kv/untyped_map_handle.h"

// TODO: Docs
namespace kv
{
  template <typename K, typename KSerialiser>
  class ReadableSetHandle
  {
  protected:
    kv::untyped::MapHandle& read_handle;

  public:
    using KeyType = K;

    ReadableSetHandle(kv::untyped::MapHandle& uh) : read_handle(uh) {}

    bool contains(const K& key)
    {
      return read_handle.has(KSerialiser::to_serialised(key));
    }

    std::optional<Version> get_version_of_previous_write(const K& key)
    {
      return read_handle.get_version_of_previous_write(
        KSerialiser::to_serialised(key));
    }

    template <class F>
    void foreach(F&& f)
    {
      auto g = [&](
                 const kv::serialisers::SerialisedEntry& k_rep,
                 const kv::serialisers::SerialisedEntry&) {
        return f(KSerialiser::from_serialised(k_rep));
      };
      read_handle.foreach(g);
    }

    size_t size()
    {
      return read_handle.size();
    }
  };

  template <typename K, typename KSerialiser>
  class WriteableSetHandle
  {
  protected:
    kv::untyped::MapHandle& write_handle;

  public:
    WriteableSetHandle(kv::untyped::MapHandle& uh) : write_handle(uh) {}

    void insert(const K& key)
    {
      write_handle.put(KSerialiser::to_serialised(key), kv::Unit::get());
    }

    bool remove(const K& key)
    {
      return write_handle.remove(KSerialiser::to_serialised(key));
    }

    void clear()
    {
      write_handle.clear();
    }
  };

  template <typename K, typename KSerialiser>
  class SetHandle : public kv::AbstractHandle,
                    public ReadableSetHandle<K, KSerialiser>,
                    public WriteableSetHandle<K, KSerialiser>
  {
  protected:
    kv::untyped::MapHandle untyped_handle;

    using ReadableBase = ReadableSetHandle<K, KSerialiser>;
    using WriteableBase = WriteableSetHandle<K, KSerialiser>;

  public:
    SetHandle(kv::untyped::ChangeSet& changes, const std::string& map_name) :
      ReadableBase(untyped_handle),
      WriteableBase(untyped_handle),
      untyped_handle(changes, map_name)
    {}
  };
}
