// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/untyped_map_handle.h"
#include "kv_types.h"

namespace kv
{
  /** Grants read access to a @c kv::Value, as part of a @c kv::Tx.
   */
  template <typename V, typename VSerialiser, typename Unit>
  class ReadableValueHandle
  {
  protected:
    kv::untyped::MapHandle& read_handle;

  public:
    using ValueType = V;

    ReadableValueHandle(kv::untyped::MapHandle& uh) : read_handle(uh) {}

    /** Get the stored value.
     *
     * This will return nullopt of the value has never been set, or has been
     * removed.
     *
     * @return Optional containing associated value, or empty if the value
     * doesn't exist
     */
    std::optional<V> get()
    {
      const auto opt_v_rep = read_handle.get(Unit::get());

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    /** Get globally committed value, which has been replicated and
     * acknowledged by consensus protocol.
     *
     * @return Optional containing associated value, or empty if the value
     * doesn't exist in globally committed state
     */
    std::optional<V> get_globally_committed()
    {
      const auto opt_v_rep = read_handle.get_globally_committed(Unit::get());

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    /** Test if value is defined.
     *
     * This is equivalent to `get().has_value()`, but is more efficient as it
     * doesn't need to deserialise the value.
     *
     * @return Boolean true iff value is defined
     */
    bool has()
    {
      return read_handle.has(Unit::get());
    }

    /** Get version when this value was last written to, by a previous
     * transaction.
     *
     * @see kv::ReadableMapHandle::get_version_of_previous_write
     *
     * @return Optional containing version of applied transaction which last
     * wrote to this value, or nullopt if such a version does not exist
     */
    std::optional<Version> get_version_of_previous_write()
    {
      return read_handle.get_version_of_previous_write(Unit::get());
    }
  };

  /** Grants write access to a @c kv::Value, as part of a @c kv::Tx.
   */
  template <typename V, typename VSerialiser, typename Unit>
  class WriteableValueHandle
  {
  protected:
    kv::untyped::MapHandle& write_handle;

  public:
    WriteableValueHandle(kv::untyped::MapHandle& uh) : write_handle(uh) {}

    /** Modify this value.
     *
     * If this value was previously defined, it will be overwritten. Even if the
     * previous value was identical, this produces a serialised write in the
     * ledger.
     *
     * @param value Value
     */
    void put(const V& value)
    {
      write_handle.put(Unit::get(), VSerialiser::to_serialised(value));
    }

    /** Delete this value, restoring its original undefined state.
     */
    void clear()
    {
      write_handle.clear();
    }
  };

  /** Grants read and write access to a @c kv::Value, as part of a @c kv::Tx.
   *
   * @see kv::ReadableValueHandle
   * @see kv::WriteableValueHandle
   */
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
