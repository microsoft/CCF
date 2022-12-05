// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/untyped_map_handle.h"

namespace kv
{
  /** Grants read access to a @c kv::Map, as part of a @c kv::Tx.
   */
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class ReadableMapHandle
  {
  protected:
    kv::untyped::MapHandle& read_handle;

  public:
    using KeyType = K;
    using ValueType = V;

    ReadableMapHandle(kv::untyped::MapHandle& uh) : read_handle(uh) {}

    /** Get name of this map.
     *
     * @return String containing name used to construct this map handle
     */
    std::string get_name_of_map() const
    {
      return read_handle.get_name_of_map();
    }

    /** Get value for key.
     *
     * This returns the value for the key as seen by this transaction. If the
     * key has been updated in the current transaction, that update will be
     * reflected in the return of this call. Where the key has not been
     * modified, this returns the state of a snapshot version from the start of
     * the transaction's execution.
     *
     * @param key Key to read
     *
     * @return Optional containing associated value, or empty if the key doesn't
     * exist
     */
    std::optional<V> get(const K& key)
    {
      const auto opt_v_rep = read_handle.get(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(*opt_v_rep);
      }

      return std::nullopt;
    }

    /** Get globally committed value for key, which has been replicated and
     * acknowledged by consensus protocol.
     *
     * This reads a globally replicated value for the specified key.
     * The value will have been the most recent replicated value when the
     * transaction began. Consensus may have advanced and committed a more
     * recent version while this transaction executes. This is undetectable to
     * the transaction.
     *
     * @param key Key to read
     *
     * @return Optional containing associated value, or empty if the key doesn't
     * exist in globally committed state
     */
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

    /** Test if key is present.
     *
     * This obeys the same rules as @c get regarding key visibility, but is more
     * efficient if you do not need the associated value.
     *
     * @param key Key to read
     *
     * @return Boolean true iff key exists
     */
    bool has(const K& key)
    {
      return read_handle.has(KSerialiser::to_serialised(key));
    }

    /** Get version when this key was last written to, by a previous
     * transaction.
     *
     * Returns nullopt when there is no value, because the key has no value
     * (never existed or has been removed). Note that this is always talking
     * about the version of previously applied state and not the same values
     * as @c get or @c has. This current transaction's pending writes have no
     * version yet, and this method does not talk about them.
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

    /** Iterate over all entries in the map.
     *
     * The passed functor should have the signature
     * `bool(const K& k, const V& v)`.
     * The iteration order is undefined.
     * Return true to continue iteration, or return false from any invocation to
     * terminate the iteration at that point - the functor will not be invoked
     * again after it returns false.
     *
     * The set of key-value entries which will be iterated over is determined at
     * the point foreach is called, and does not include any modifications made
     * by the functor. This means:
     * - If the functor sets a value V at a new key K', the functor will not be
     * called for (K', V)
     * - If the functor changes the value at key K from V to V', the functor
     * will be called with the old value (K, V), not the new value (K, V')
     * - If the functor removes K, the functor will still be called for (K, V)
     *
     * Calling @c get will always return the true latest state; the iterator
     * visibility described above only applies to the keys and values passed to
     * this functor.
     *
     * @tparam F Functor type. Should usually be derived implicitly from f
     * @param f Functor instance, taking (const K& k, const V& v) and returning
     * a bool. Return value determines whether the iteration should continue
     * (true) or stop (false)
     */
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

    /** Iterate over all keys in the map.
     *
     * Similar to @c foreach but the functor takes a single key argument rather
     * than a key and value. Avoids deserialisation of values.
     *
     * @tparam F Functor type. Should usually be derived implicitly from f
     * @param f Functor instance, taking (const K& k) and returning
     * a bool. Return value determines whether the iteration should continue
     * (true) or stop (false)
     */
    template <class F>
    void foreach_key(F&& f)
    {
      auto g = [&](
                 const kv::serialisers::SerialisedEntry& k_rep,
                 const kv::serialisers::SerialisedEntry&) {
        return f(KSerialiser::from_serialised(k_rep));
      };
      read_handle.foreach(g);
    }

    /** Iterate over all values in the map.
     *
     * Similar to @c foreach but the functor takes a single value argument
     * rather than a key and value. Avoids deserialisation of keys.
     *
     * @tparam F Functor type. Should usually be derived implicitly from f
     * @param f Functor instance, taking (const V& v) and returning
     * a bool. Return value determines whether the iteration should continue
     * (true) or stop (false)
     */
    template <class F>
    void foreach_value(F&& f)
    {
      auto g = [&](
                 const kv::serialisers::SerialisedEntry&,
                 const kv::serialisers::SerialisedEntry& v_rep) {
        return f(VSerialiser::from_serialised(v_rep));
      };
      read_handle.foreach(g);
    }

    /** Returns number of entries in this map.
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

  /** Grants write access to a @c kv::Map, as part of a @c kv::Tx.
   */
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class WriteableMapHandle
  {
  protected:
    kv::untyped::MapHandle& write_handle;

  public:
    WriteableMapHandle(kv::untyped::MapHandle& uh) : write_handle(uh) {}

    /** Write value at key.
     *
     * If the key already exists, the previous value will be replaced with the
     * new value.
     *
     * @param key Key at which to insert
     * @param value Associated value to be inserted
     */
    void put(const K& key, const V& value)
    {
      write_handle.put(
        KSerialiser::to_serialised(key), VSerialiser::to_serialised(value));
    }

    /** Delete a key-value pair.
     *
     * It is safe to call this on non-existent keys.
     *
     * @param key Key to be removed
     */
    void remove(const K& key)
    {
      write_handle.remove(KSerialiser::to_serialised(key));
    }

    /** Delete every key-value pair.
     */
    void clear()
    {
      write_handle.clear();
    }
  };

  /** Grants read and write access to a @c kv::Map, as part of a @c kv::Tx.
   *
   * @see kv::ReadableMapHandle
   * @see kv::WriteableMapHandle
   */
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class MapHandle : public AbstractHandle,
                    public ReadableMapHandle<K, V, KSerialiser, VSerialiser>,
                    public WriteableMapHandle<K, V, KSerialiser, VSerialiser>
  {
  protected:
    kv::untyped::MapHandle untyped_handle;

    using ReadableBase = ReadableMapHandle<K, V, KSerialiser, VSerialiser>;
    using WriteableBase = WriteableMapHandle<K, V, KSerialiser, VSerialiser>;

  public:
    MapHandle(kv::untyped::ChangeSet& changes, const std::string& map_name) :
      ReadableBase(untyped_handle),
      WriteableBase(untyped_handle),
      untyped_handle(changes, map_name)
    {}
  };
}
