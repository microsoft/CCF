// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/untyped_map_diff.h"

#include "kv/untyped_change_set.h"

namespace kv::untyped
{
  void MapDiff::foreach_(const MapDiff::ElementVisitorWithEarlyOut& f)
  {
    for (auto write = writes.begin(); write != writes.end(); ++write)
    {
      bool should_continue = f(write->first, write->second);

      if (!should_continue)
      {
        break;
      }
    }
  }

  MapDiff::MapDiff(kv::untyped::ChangeSet& cs, const std::string& map_name) :
    writes(cs.writes),
    map_name(map_name)
  {}

  std::optional<std::optional<MapDiff::ValueType>> MapDiff::get(
    const MapDiff::KeyType& key)
  {
    auto val_opt = writes.find(key);
    if (val_opt != writes.end())
    {
      LOG_TRACE_FMT("KV[{}]::get({}) - found", map_name, key);
      return val_opt->second;
    }

    LOG_TRACE_FMT("KV[{}]::get({}) - not found", map_name, key);

    return std::nullopt;
  }

  bool MapDiff::has(const MapDiff::KeyType& key)
  {
    auto val_opt = writes.find(key);

    bool found = false;

    if (val_opt != writes.end())
    {
      found = val_opt->second.has_value();
    }

    LOG_TRACE_FMT(
      "KV[{}]::has({}) - {}found", map_name, key, found ? "" : "not ");
    return found;
  }

  bool MapDiff::is_deleted(const MapDiff::KeyType& key)
  {
    auto val_opt = writes.find(key);

    bool deleted = false;

    if (val_opt != writes.end())
    {
      deleted = !val_opt->second.has_value();
    }

    LOG_TRACE_FMT(
      "KV[{}]::deleted({}) - {}deleted", map_name, key, deleted ? "" : "not ");
    return deleted;
  }

  void MapDiff::foreach(const MapDiff::ElementVisitorWithEarlyOut& f)
  {
    foreach_(f);
  }

  size_t MapDiff::size()
  {
    size_t size_ = 0;

    foreach([&size_](const auto&, const auto&) {
      ++size_;
      return true;
    });

    return size_;
  }

  void MapDiff::range(
    const MapDiff::ElementVisitor& f,
    const std::optional<MapDiff::KeyType>& from,
    const std::optional<MapDiff::KeyType>& to)
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

    std::map<KeyType, std::optional<ValueType>> res;
    auto g = [&res, &from, &to, continue_past_range_to](
               const KeyType& k, const std::optional<ValueType>& v) {
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
    foreach_(g);

    for (const auto& e : res)
    {
      f(e.first, e.second);
    }
  }
}