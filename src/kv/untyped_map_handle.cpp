// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/untyped_map_handle.h"

#include "kv/untyped_change_set.h"

namespace kv::untyped
{
  const MapHandle::ValueType* MapHandle::read_key(const KeyType& key)
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

    // Return the value.
    return &search->value;
  }

  void MapHandle::foreach_state_and_writes(
    const MapHandle::ElementVisitorWithEarlyOut& f, bool always_consider_writes)
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

        if (write == w.end())
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

  MapHandle::MapHandle(
    kv::untyped::ChangeSet& cs, const std::string& map_name) :
    tx_changes(cs),
    map_name(map_name)
  {}

  std::string MapHandle::get_name_of_map() const
  {
    return map_name;
  }

  std::optional<MapHandle::ValueType> MapHandle::get(
    const MapHandle::KeyType& key)
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

  std::optional<Version> MapHandle::get_version_of_previous_write(
    const MapHandle::KeyType& key)
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

    return search->version;
  }

  std::optional<MapHandle::ValueType> MapHandle::get_globally_committed(
    const MapHandle::KeyType& key)
  {
    // If there is no committed value, return empty.
    auto search = tx_changes.committed.get(key);
    if (!search.has_value())
    {
      return std::nullopt;
    }

    // Return the value.
    return search->value;
  }

  bool MapHandle::has(const MapHandle::KeyType& key)
  {
    auto versionv_p = read_key(key);
    auto found = versionv_p != nullptr;
    LOG_TRACE_FMT(
      "KV[{}]::has({}) - {}found", map_name, key, found ? "" : "not ");
    return found;
  }

  void MapHandle::put(
    const MapHandle::KeyType& key, const MapHandle::ValueType& value)
  {
    LOG_TRACE_FMT("KV[{}]::put({}, {})", map_name, key, value);
    // Record in the write set.
    tx_changes.writes[key] = value;
  }

  void MapHandle::remove(const MapHandle::KeyType& key)
  {
    LOG_TRACE_FMT("KV[{}]::remove({})", map_name, key);
    // Record in the write set
    tx_changes.writes[key] = std::nullopt;
  }

  void MapHandle::clear()
  {
    foreach([this](const auto& k, const auto&) {
      remove(k);
      return true;
    });
  }

  void MapHandle::foreach(const MapHandle::ElementVisitorWithEarlyOut& f)
  {
    foreach_state_and_writes(f, false);
  }

  size_t MapHandle::size()
  {
    size_t size_ = 0;

    foreach([&size_](const auto&, const auto&) {
      ++size_;
      return true;
    });

    return size_;
  }

  void MapHandle::range(
    const MapHandle::ElementVisitor& f,
    const std::optional<MapHandle::KeyType>& from,
    const std::optional<MapHandle::KeyType>& to)
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

    if (
      from.has_value() && to.has_value() &&
      (from.value() == to.value() || to.value() < from.value()))
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
      if (from.has_value() && k < from.value())
      {
        // Start of range is not yet found.
        return true;
      }
      else if (to.has_value() && (k == to.value() || to.value() < k))
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
}