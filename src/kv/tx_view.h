// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/champ_map.h"
#include "kv_types.h"

#include <unordered_map>

namespace kv
{
  static bool is_deleted(Version version)
  {
    return version < 0;
  }

  template <typename V>
  struct VersionV
  {
    Version version;
    V value;

    VersionV() = default;
    VersionV(Version ver, V val) : version(ver), value(val) {}
  };

  template <typename K, typename V, typename H>
  using State = champ::Map<K, VersionV<V>, H>;

  template <typename K, typename V, typename H>
  using Read = std::unordered_map<K, Version, H>;

  template <typename K, typename V, typename H>
  using Write = std::unordered_map<K, VersionV<V>, H>;

  template <typename K, typename V, typename H>
  class TxView
  {
  protected:
    using VersionV = VersionV<V>;
    using State = State<K, V, H>;
    using Read = Read<K, V, H>;
    using Write = Write<K, V, H>;

    State state;
    State committed;
    Version start_version;

    Read reads = {};
    Write writes = {};
    Version read_version = NoVersion;

  public:
    TxView(State& current_state, State& committed_state, Version v) :
      state(current_state),
      committed(committed_state),
      start_version(v)
    {}

    /** Get value for key
     *
     * This returns the value for the key inside the transaction. If the key
     * has been updated in the current transaction, that update will be
     * reflected in the return of this call.
     *
     * @param key Key
     *
     * @return optional containing value, empty if the key doesn't exist
     */
    std::optional<V> get(const K& key)
    {
      // A write followed by a read doesn't introduce a read dependency.
      // If we have written, return the value without updating the read set.
      auto write = writes.find(key);
      if (write != writes.end())
      {
        // Return empty for a key that has been removed.
        if (is_deleted(write->second.version))
        {
          return std::nullopt;
        }

        return write->second.value;
      }

      // If the key doesn't exist, return empty and record that we depend on
      // the key not existing.
      auto search = state.get(key);
      if (!search.has_value())
      {
        reads.insert(std::make_pair(key, NoVersion));
        return std::nullopt;
      }

      // Record the version that we depend on.
      auto& found = search.value();
      reads.insert(std::make_pair(key, found.version));

      // If the key has been deleted, return empty.
      if (is_deleted(found.version))
      {
        return std::nullopt;
      }

      // Return the value.
      return found.value;
    }

    /** Get globally committed value for key
     *
     * This reads a globally replicated value for the specified key.
     * The value will have been the replicated value when the transaction
     * began, but the map may be compacted while the transaction is in
     * flight. If that happens, there may be a more recent committed
     * version. This is undetectable to the transaction.
     *
     * @param key Key
     *
     * @return optional containing value, empty if the key doesn't exist in
     * globally committed state
     */
    std::optional<V> get_globally_committed(const K& key)
    {
      // If there is no committed value, return empty.
      auto search = committed.get(key);
      if (!search.has_value())
      {
        return std::nullopt;
      }

      // If the key has been deleted, return empty.
      auto& found = search.value();
      if (is_deleted(found.version))
      {
        return std::nullopt;
      }

      // Return the value.
      return found.value;
    }

    /** Write value at key
     *
     * If the key already exists, the value will be replaced.
     * This will fail if the transaction is already committed.
     *
     * @param key Key
     * @param value Value
     *
     * @return true if successful, false otherwise
     */
    bool put(const K& key, const V& value)
    {
      // Record in the write set.
      writes[key] = {0, value};
      return true;
    }

    /** Remove key
     *
     * This will fail if the key does not exist, or if the transaction
     * is already committed.
     *
     * @param key Key
     *
     * @return true if successful, false otherwise
     */
    bool remove(const K& key)
    {
      auto write = writes.find(key);
      auto search = state.get(key).has_value();

      if (write != writes.end())
      {
        if (!search)
        {
          // this key only exists locally, there is no reason to maintain and
          // serialise it
          writes.erase(key);
        }
        else
        {
          // If we have written, change the write set to indicate a remove.
          write->second = {NoVersion, V()};
        }

        return true;
      }

      // If the key doesn't exist, return false.
      if (!search)
      {
        return false;
      }

      // Record in the write set.
      writes.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(key),
        std::forward_as_tuple(NoVersion, V()));
      return true;
    }

    /** Iterate over all entries in the map
     *
     * @param F functor, taking a key and a value, return value determines
     * whether the iteration should continue (true) or stop (false)
     */
    template <class F>
    bool foreach(F&& f)
    {
      // Record a global read dependency.
      read_version = start_version;
      auto& w = writes;

      state.foreach([&w, &f](const K& k, const VersionV& v) {
        auto write = w.find(k);

        if ((write == w.end()) && !is_deleted(v.version))
          return f(k, v.value);
        return true;
      });

      for (auto write = writes.begin(); write != writes.end(); ++write)
      {
        if (!is_deleted(write->second.version))
          if (!f(write->first, write->second.value))
            return false;
      }
      return true;
    }
  };
}