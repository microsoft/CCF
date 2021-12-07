// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/change_set.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry.h"

namespace kv::untyped
{
  using SerialisedEntry = kv::serialisers::SerialisedEntry;
  using SerialisedKeyHasher = std::hash<SerialisedEntry>;

  using VersionV = kv::VersionV<SerialisedEntry>;
  using State =
    kv::State<SerialisedEntry, SerialisedEntry, SerialisedKeyHasher>;
  using Read = kv::Read<SerialisedEntry>;
  using Write = kv::Write<SerialisedEntry, SerialisedEntry>;
  using ChangeSet =
    kv::ChangeSet<SerialisedEntry, SerialisedEntry, SerialisedKeyHasher>;
  using ChangeSetPtr = std::unique_ptr<ChangeSet>;
  using SnapshotChangeSet = kv::
    SnapshotChangeSet<SerialisedEntry, SerialisedEntry, SerialisedKeyHasher>;

  class MapHandle : public kv::AbstractHandle
  {
  public:
    // Expose these types so that other code can use them as MyTx::KeyType or
    // MyMap::MapHandle::KeyType, templated on the MapHandle or Map type
    using KeyType = SerialisedEntry;
    using ValueType = SerialisedEntry;

  protected:
    ChangeSet& tx_changes;
    std::string map_name;

    /** Get pointer to current value if this key exists, else nullptr if it does
     * not exist or has been deleted. If non-null, points to something owned by
     * tx_changes - expect this is used/dereferenced immediately, and there is
     * no concurrent access which could invalidate it. Modifies read set if
     * appropriate to record read dependency on this key, at the version of the
     * returned data.
     */
    const ValueType* read_key(const KeyType& key)
    {
      // A write followed by a read doesn't introduce a read dependency.
      // If we have written, return the value without updating the read set.
      auto write = tx_changes.writes.find(key);
      if (write != tx_changes.writes.end())
      {
        if (write->second.has_value())
        {
          return &write->second.value();
        }
        else
        {
          return nullptr;
        }
      }

      // If the key doesn't exist, return empty and record that we depend on
      // the key not existing.
      const auto search = tx_changes.state.getp(key);
      if (search == nullptr)
      {
        tx_changes.reads.insert(
          std::make_pair(key, std::make_tuple(NoVersion, NoVersion)));
        return nullptr;
      }

      // Record the version that we depend on.
      tx_changes.reads.insert(std::make_pair(
        key, std::make_tuple(search->version, search->read_version)));

      // If the key has been deleted, return empty.
      if (is_deleted(search->version))
      {
        return nullptr;
      }

      // Return the value.
      return &search->value;
    }

    template <class F>
    void foreach_state_and_writes(F&& f, bool always_consider_writes)
    {
      // Record a global read dependency.
      tx_changes.read_version = tx_changes.start_version;

      // Take a snapshot copy of the writes. This is what we will iterate over,
      // while any additional modifications made by the functor will modify the
      // original tx_changes.writes, and be visible outside of the functor's
      // args
      auto w = tx_changes.writes;
      bool should_continue = true;

      tx_changes.state.foreach(
        [&w, &f, &should_continue](const KeyType& k, const VersionV& v) {
          auto write = w.find(k);

          if ((write == w.end()) && !is_deleted(v.version))
          {
            should_continue = f(k, v.value);
          }

          return should_continue;
        });

      if (always_consider_writes || should_continue)
      {
        for (auto write = w.begin(); write != w.end(); ++write)
        {
          if (write->second.has_value())
          {
            should_continue = f(write->first, write->second.value());
          }

          if (!should_continue)
          {
            break;
          }
        }
      }
    }

  public:
    MapHandle(ChangeSet& cs, const std::string& map_name) :
      tx_changes(cs),
      map_name(map_name)
    {}

    std::optional<ValueType> get(const KeyType& key)
    {
      auto value_p = read_key(key);
      auto found = value_p != nullptr;
      LOG_TRACE_FMT(
        "KV[{}]::get({}) - {}found", map_name, key, found ? "" : "not ");
      if (!found)
      {
        return std::nullopt;
      }

      return *value_p;
    }

    std::optional<Version> get_version_of_previous_write(const KeyType& key)
    {
      // If the key doesn't exist, return empty and record that we depend on
      // the key not existing.
      const auto search = tx_changes.state.getp(key);
      if (search == nullptr)
      {
        tx_changes.reads.insert(
          std::make_pair(key, std::make_tuple(NoVersion, NoVersion)));
        return std::nullopt;
      }

      // Record the version that we depend on.
      tx_changes.reads.insert(std::make_pair(
        key, std::make_tuple(search->version, search->read_version)));

      // If the key has been deleted, return empty. NB: We still depend on this
      // version with the call above, but we don't distinguish deleted from
      // non-existent in the returned values.
      if (is_deleted(search->version))
      {
        return std::nullopt;
      }

      return search->version;
    }

    std::optional<ValueType> get_globally_committed(const KeyType& key)
    {
      // If there is no committed value, return empty.
      auto search = tx_changes.committed.get(key);
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

    bool has(const KeyType& key)
    {
      auto versionv_p = read_key(key);
      auto found = versionv_p != nullptr;
      LOG_TRACE_FMT(
        "KV[{}]::has({}) - {}found", map_name, key, found ? "" : "not ");
      return found;
    }

    void put(const KeyType& key, const ValueType& value)
    {
      LOG_TRACE_FMT("KV[{}]::put({}, {})", map_name, key, value);
      // Record in the write set.
      tx_changes.writes[key] = value;
    }

    bool remove(const KeyType& key)
    {
      LOG_TRACE_FMT("KV[{}]::remove({})", map_name, key);
      auto write = tx_changes.writes.find(key);
      auto exists_in_state = tx_changes.state.getp(key) != nullptr;

      if (write != tx_changes.writes.end())
      {
        if (!exists_in_state)
        {
          // this key only exists locally, there is no reason to maintain and
          // serialise it
          tx_changes.writes.erase(key);
        }
        else
        {
          // If we have written, change the write set to indicate a remove.
          write->second = std::nullopt;
        }

        return true;
      }

      // If the key doesn't exist, return false.
      if (!exists_in_state)
      {
        return false;
      }

      // Record in the write set.
      tx_changes.writes[key] = std::nullopt;
      return true;
    }

    void clear()
    {
      foreach([this](const auto& k, const auto&) {
        remove(k);
        return true;
      });
    }

    template <class F>
    void foreach(F&& f)
    {
      foreach_state_and_writes(std::forward<F>(f), false);
    }

    size_t size()
    {
      size_t size_ = 0;

      foreach([&size_](const auto&, const auto&) {
        ++size_;
        return true;
      });

      return size_;
    }

    // Returns a map of keys to values between [from, to).
    template <class F>
    void range(F&& f, const KeyType& from, const KeyType& to)
    {
      // Current limitations/ineficiencies:
      // - The state and writes are wastefully looped over until `from` is
      // found.
      // - All keys and values in the range are stored in the intermediate map
      // `res`.
      // - The constructed range is loop over at the end to call lambda on.
      // Optimisation is possible to only loop over the state/writes once, in
      // order, and call the user lambda on each element in the range directly.
      // This should include adding an iterator to underlying ordered state
      // (i.e. rb::Map) to find the start/end of the range using
      // std::lower_bound()/std::upper_bound() and loop over it, interleaves
      // with the local writes.

      if (from == to || to < from)
      {
        return;
      }

      // Since entries are ordered in the RB Map, it is OK to early out once we
      // have passed the end of the range. Otherwise (CHAMP), all entries should
      // be considered.
#ifndef KV_STATE_RB
      bool continue_past_range_to = true;
#else
      bool continue_past_range_to = false;
#endif

      std::map<KeyType, ValueType> res;
      auto g = [&res, &from, &to, continue_past_range_to](
                 const KeyType& k, const ValueType& v) {
        if (k < from)
        {
          // Start of range is not yet found.
          return true;
        }
        else if (k == to || to < k)
        {
          // End of range. Note: `to` is excluded.
          return continue_past_range_to;
        }

        res[k] = v;
        return true;
      };
      foreach_state_and_writes(g, true);

      for (const auto& e : res)
      {
        f(e.first, e.second);
      }
    }
  };
}