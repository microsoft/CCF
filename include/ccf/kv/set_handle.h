// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/unit.h"
#include "ccf/kv/untyped_map_handle.h"

namespace ccf::kv
{
  /** Grants read access to a @c ccf::kv::Set, as part of a @c ccf::kv::Tx.
   */
  template <typename K, typename KSerialiser>
  class ReadableSetHandle
  {
  protected:
    ccf::kv::untyped::MapHandle& read_handle;

  public:
    using KeyType = K;

    ReadableSetHandle(ccf::kv::untyped::MapHandle& uh) : read_handle(uh) {}

    /** Test whether a key is present in the set.
     *
     * This returns true if the key is present, including if it was added to the
     * set during this transaction.
     *
     * @param key Key to test
     *
     * @return Boolean true iff key exists
     */
    bool contains(const K& key)
    {
      return read_handle.has(KSerialiser::to_serialised(key));
    }

    /** Test whether a key's presence is globally committed, meaning it has been
     * replciated and acknowledged by consensus protocol.
     *
     * @see ccf::kv::ReadableMapHandle::get_globally_committed
     *
     * @param key Key to test
     *
     * @return Boolean true iff key exists in globally committed state
     */
    bool contains_globally_committed(const K& key)
    {
      return read_handle.has_globally_committed(
        KSerialiser::to_serialised(key));
    }

    /** Get version when this key was last added to the set.
     *
     * Returns nullopt if the key is not present.
     *
     * @see ccf::kv::ReadableMapHandle::get_version_of_previous_write
     *
     * @param key Key to read
     *
     * @return Optional containing version of applied transaction which last
     * wrote at this key, or nullopt if such a version does not exist
     */
    std::optional<Version> get_version_of_previous_write(const K& key)
    {
      return read_handle.get_version_of_previous_write(
        KSerialiser::to_serialised(key));
    }

    /** Iterate over all entries in this set.
     *
     * @see ccf::kv::ReadableMapHandle::foreach
     *
     * @tparam F Functor type. Should usually be derived implicitly from f
     * @param f Functor instance, taking (const K& k) and returning a
     * bool. Return value determines whether the iteration should continue
     * (true) or stop (false)
     */
    template <class F>
    void foreach(F&& f) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
      auto g = [&](
                 const ccf::kv::serialisers::SerialisedEntry& k_rep,
                 const ccf::kv::serialisers::SerialisedEntry&) {
        return f(KSerialiser::from_serialised(k_rep));
      };
      read_handle.foreach(g);
    }

    /** Returns number of entries in this set.
     *
     * This is the count of all currently present keys, including both those
     * which were already committed and any modifications (taking into account
     * new additions or removals) that have been made during this transaction.
     *
     * @return Count of entries
     */
    size_t size()
    {
      return read_handle.size();
    }
  };

  /** Grants write access to a @c ccf::kv::Set, as part of a @c ccf::kv::Tx.
   */
  template <typename K, typename KSerialiser, typename Unit>
  class WriteableSetHandle
  {
  protected:
    ccf::kv::untyped::MapHandle& write_handle;

  public:
    WriteableSetHandle(ccf::kv::untyped::MapHandle& uh) : write_handle(uh) {}

    /** Insert an element into this set.
     *
     * This will always insert a value, producing a new write and updating
     * future calls to @c ReadableSetHandle::get_version_of_previous_write, even
     * if this key was already present.
     *
     * @param key Key to insert
     */
    void insert(const K& key)
    {
      write_handle.put(KSerialiser::to_serialised(key), Unit::get());
    }

    /** Delete an element from this set.
     *
     * It is safe to call this on non-existent keys.
     *
     * @param key Key to delete
     */
    void remove(const K& key)
    {
      write_handle.remove(KSerialiser::to_serialised(key));
    }

    /** Delete every element in this set.
     */
    void clear()
    {
      write_handle.clear();
    }
  };

  /** Grants read and write access to a @c ccf::kv::Set, as part of a @c
   * ccf::kv::Tx.
   *
   * @see ccf::kv::ReadableSetHandle
   * @see ccf::kv::WriteableSetHandle
   */
  template <typename K, typename KSerialiser, typename Unit>
  class SetHandle : public ccf::kv::AbstractHandle,
                    public ReadableSetHandle<K, KSerialiser>,
                    public WriteableSetHandle<K, KSerialiser, Unit>
  {
  protected:
    ccf::kv::untyped::MapHandle untyped_handle;

    using ReadableBase = ReadableSetHandle<K, KSerialiser>;
    using WriteableBase = WriteableSetHandle<K, KSerialiser, Unit>;

  public:
    SetHandle(
      ccf::kv::untyped::ChangeSet& changes, const std::string& map_name) :
      ReadableBase(untyped_handle),
      WriteableBase(untyped_handle),
      untyped_handle(changes, map_name)
    {}
  };
}
