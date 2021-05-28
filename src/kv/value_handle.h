// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/untyped_map_handle.h"
#include "kv_types.h"

// TODO: Docs
namespace kv
{
  template <typename V, typename VSerialiser, typename Unit>
  class ReadableValueHandle
  {
  protected:
    kv::untyped::MapHandle& read_handle;

  public:
    using ValueType = V;

    ReadableValueHandle(kv::untyped::MapHandle& uh) : read_handle(uh) {}

    std::optional<V> get()
    {
      const auto opt_v_rep = read_handle.get(Unit::get());

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    bool has()
    {
      return read_handle.has(Unit::get());
    }

    std::optional<Version> get_version_of_previous_write()
    {
      return read_handle.get_version_of_previous_write(Unit::get());
    }
  };

  template <typename V, typename VSerialiser, typename Unit>
  class WriteableValueHandle
  {
  protected:
    kv::untyped::MapHandle& write_handle;

  public:
    WriteableValueHandle(kv::untyped::MapHandle& uh) : write_handle(uh) {}

    void put(const V& value)
    {
      write_handle.put(Unit::get(), VSerialiser::to_serialised(value));
    }

    void clear()
    {
      write_handle.clear();
    }
  };

  template <typename V, typename VSerialiser, typename Unit>
  class ValueHandle : public AbstractHandle,
                      public ReadableValueHandle<V, VSerialiser, Unit>,
                      public WriteableValueHandle<V, VSerialiser, Unit>
  {
  protected:
    kv::untyped::MapHandle untyped_handle;

    using ReadableBase = ReadableValueHandle<V, VSerialiser, Unit>;
    using WriteableBase = WriteableValueHandle<V, VSerialiser, Unit>;

  public:
    ValueHandle(kv::untyped::ChangeSet& changes, const std::string& map_name) :
      ReadableBase(untyped_handle),
      WriteableBase(untyped_handle),
      untyped_handle(changes, map_name)
    {}
  };
}
