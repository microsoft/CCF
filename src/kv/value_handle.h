// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/untyped_map_handle.h"
#include "kv_types.h"

// TODO: Docs
namespace kv
{
  template <typename V, typename VSerialiser>
  class ReadableValueHandle
  {
  protected:
    kv::untyped::MapHandle& read_handle;

  public:
    using ValueType = V;

    ReadableValueHandle(kv::untyped::MapHandle& uh) : read_handle(uh) {}

    std::optional<V> get()
    {
      const auto opt_v_rep = read_handle.get(kv::Unit::get());

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    bool has()
    {
      return read_handle.has(kv::Unit::get());
    }

    std::optional<Version> get_version_of_previous_write()
    {
      return read_handle.get_version_of_previous_write(kv::Unit::get());
    }
  };

  template <typename V, typename VSerialiser>
  class WriteableValueHandle
  {
  protected:
    kv::untyped::MapHandle& write_handle;

  public:
    WriteableValueHandle(kv::untyped::MapHandle& uh) : write_handle(uh) {}

    void put(const V& value)
    {
      write_handle.put(kv::Unit::get(), VSerialiser::to_serialised(value));
    }

    void clear()
    {
      write_handle.clear();
    }
  };

  template <typename V, typename VSerialiser>
  class ValueHandle : public AbstractHandle,
                      public ReadableValueHandle<V, VSerialiser>,
                      public WriteableValueHandle<V, VSerialiser>
  {
  protected:
    kv::untyped::MapHandle untyped_handle;

    using ReadableBase = ReadableValueHandle<V, VSerialiser>;
    using WriteableBase = WriteableValueHandle<V, VSerialiser>;

  public:
    ValueHandle(kv::untyped::ChangeSet& changes, const std::string& map_name) :
      ReadableBase(untyped_handle),
      WriteableBase(untyped_handle),
      untyped_handle(changes, map_name)
    {}
  };
}
