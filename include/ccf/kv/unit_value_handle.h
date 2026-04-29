// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/unit.h"
#include "ccf/kv/untyped_map_handle.h"

namespace ccf::kv
{
  /** Grants read access to a @c ccf::kv::UnitValue, as part of a @c
   * ccf::kv::Tx.
   */
  template <typename Unit>
  class ReadableUnitValueHandle
  {
  protected:
    ccf::kv::untyped::MapHandle& read_handle;

  public:
    ReadableUnitValueHandle(ccf::kv::untyped::MapHandle& uh) : read_handle(uh)
    {}

    /** Test if the value has been touched.
     *
     * @return Boolean true iff the value is defined
     */
    bool has()
    {
      return read_handle.has(Unit::get());
    }

    /** Get version when this value was last written to, by a previous
     * transaction.
     *
     * @see ccf::kv::ReadableMapHandle::get_version_of_previous_write
     *
     * @return Optional containing version of applied transaction which last
     * wrote to this value, or nullopt if such a version does not exist
     */
    std::optional<Version> get_version_of_previous_write()
    {
      return read_handle.get_version_of_previous_write(Unit::get());
    }
  };

  /** Grants write access to a @c ccf::kv::UnitValue, as part of a @c
   * ccf::kv::Tx.
   */
  template <typename Unit>
  class WriteableUnitValueHandle
  {
  protected:
    ccf::kv::untyped::MapHandle& write_handle;

  public:
    WriteableUnitValueHandle(ccf::kv::untyped::MapHandle& uh) : write_handle(uh)
    {}

    /** Touch this value.
     *
     * If this value was previously defined, it will be overwritten. Even if the
     * previous value was identical, this produces a serialised write in the
     * ledger.
     */
    void touch()
    {
      write_handle.put(Unit::get(), Unit::get());
    }

    /** Delete this value, restoring its original undefined state.
     */
    void clear()
    {
      write_handle.clear();
    }
  };

  /** Grants read and write access to a @c ccf::kv::UnitValue, as part of a @c
   * ccf::kv::Tx.
   *
   * @see ccf::kv::ReadableUnitValueHandle
   * @see ccf::kv::WriteableUnitValueHandle
   */
  template <typename Unit>
  class UnitValueHandle : public AbstractHandle,
                          public ReadableUnitValueHandle<Unit>,
                          public WriteableUnitValueHandle<Unit>
  {
  protected:
    ccf::kv::untyped::MapHandle untyped_handle;

    using ReadableBase = ReadableUnitValueHandle<Unit>;
    using WriteableBase = WriteableUnitValueHandle<Unit>;

  public:
    UnitValueHandle(
      ccf::kv::untyped::ChangeSet& changes, const std::string& map_name) :
      ReadableBase(untyped_handle),
      WriteableBase(untyped_handle),
      untyped_handle(changes, map_name)
    {}
  };
}
