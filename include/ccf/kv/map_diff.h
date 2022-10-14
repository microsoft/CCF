// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/untyped_map_diff.h"

namespace kv
{
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class MapDiff : public AbstractHandle
  {
  protected:
    kv::untyped::MapDiff map_diff;

  public:
    using KeyType = K;
    using ValueType = V;

    MapDiff(kv::untyped::MapDiff map_diff_) : map_diff(map_diff_) {}

    MapDiff(kv::untyped::ChangeSet& changes, const std::string& map_name) :
      map_diff(changes, map_name)
    {}

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
      const auto opt_v_rep = map_diff.get(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        return VSerialiser::from_serialised(opt_v_rep.value());
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
      return map_diff.has(KSerialiser::to_serialised(key));
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
      const auto& g =
        [&](
          const kv::serialisers::SerialisedEntry& k_rep,
          const std::optional<kv::serialisers::SerialisedEntry>& v_rep)
        -> bool {
        const auto k = KSerialiser::from_serialised(k_rep);
        if (v_rep.has_value())
        {
          const std::optional<V> v =
            VSerialiser::from_serialised(v_rep.value());
          return f(k, v);
        }
        else
        {
          const std::optional<V> v = std::nullopt;
          return f(k, v);
        }
      };
      map_diff.foreach(g);
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
      map_diff.foreach(g);
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
                 const std::optional<kv::serialisers::SerialisedEntry>& v_rep) {
        if (v_rep.has_value())
        {
          return f(VSerialiser::from_serialised(v_rep));
        }
        else
        {
          return f(std::nullopt);
        }
      };
      map_diff.foreach(g);
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
      return map_diff.size();
    }
  };
}