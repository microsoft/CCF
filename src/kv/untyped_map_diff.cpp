// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/untyped_map_diff.h"

#include "ds/internal_logger.h"
#include "kv/untyped_change_set.h"

namespace ccf::kv::untyped
{
  // A change set created for a diff (see Map::create_change_set) holds the
  // state as of its start version, and lists in writes the keys deleted by the
  // commit at that version. Puts are the entries of the state whose version is
  // the start version, so writes are only ever consulted for deletes.

  namespace
  {
    // Returns the value written at the change set's start version if key was
    // put by that commit, else nullptr. The pointer is owned by change_set.
    const MapDiff::ValueType* written_value(
      const ChangeSet& change_set, const MapDiff::KeyType& key)
    {
      const auto* const search = change_set.state.getp(key);
      if (search == nullptr || search->version != change_set.start_version)
      {
        return nullptr;
      }

      return &search->value;
    }
  }

  void MapDiff::foreach_(const MapDiff::ElementVisitorWithEarlyOut& f)
  {
    for (const auto& [key, maybe_value] : change_set.writes)
    {
      if (maybe_value.has_value())
      {
        continue;
      }

      if (!f(key, maybe_value))
      {
        return;
      }
    }

    const auto version = change_set.start_version;
    change_set.state.foreach(
      [&f, version](const KeyType& k, const VersionV& v) {
        if (v.version != version)
        {
          return true;
        }

        const std::optional<ValueType> value = v.value;
        return f(k, value);
      });
  }

  MapDiff::MapDiff(ccf::kv::untyped::ChangeSet& cs, std::string map_name) :
    change_set(cs),
    map_name(std::move(map_name))
  {}

  std::optional<std::optional<MapDiff::ValueType>> MapDiff::get(
    const MapDiff::KeyType& key)
  {
    using MaybeValue = std::optional<ValueType>;

    const auto write = change_set.writes.find(key);
    if (write != change_set.writes.end() && !write->second.has_value())
    {
      LOG_TRACE_FMT("KV[{}]::get({}) - deleted", map_name, key);
      return std::optional<MaybeValue>(std::in_place, std::nullopt);
    }

    const auto* value_p = written_value(change_set, key);
    if (value_p != nullptr)
    {
      LOG_TRACE_FMT("KV[{}]::get({}) - found", map_name, key);
      return std::optional<MaybeValue>(std::in_place, *value_p);
    }

    LOG_TRACE_FMT("KV[{}]::get({}) - not found", map_name, key);

    return std::nullopt;
  }

  bool MapDiff::has(const MapDiff::KeyType& key)
  {
    const bool found = written_value(change_set, key) != nullptr;

    LOG_TRACE_FMT(
      "KV[{}]::has({}) - {}found", map_name, key, found ? "" : "not ");
    return found;
  }

  bool MapDiff::is_deleted(const MapDiff::KeyType& key)
  {
    const auto write = change_set.writes.find(key);
    const bool deleted =
      write != change_set.writes.end() && !write->second.has_value();

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
    // This should include adding an iterator to the underlying ordered state
    // to find the start/end of the range using
    // std::lower_bound()/std::upper_bound() and loop over it, interleaves
    // with the local writes.

    if (
      from.has_value() && to.has_value() &&
      (from.value() == to.value() || to.value() < from.value()))
    {
      return;
    }

    // CHAMP maps are unordered, so we cannot early-out when we encounter a
    // key past the end of the range - there may still be in-range keys later
    // in the iteration. If the underlying state used an ordered collection,
    // this could be set to false to stop iteration once `to` is exceeded.
    bool continue_past_range_to = true;

    std::map<KeyType, std::optional<ValueType>> res;
    auto g = [&res, &from, &to, continue_past_range_to](
               const KeyType& k, const std::optional<ValueType>& v) {
      if (from.has_value() && k < from.value())
      {
        // Start of range is not yet found.
        return true;
      }

      if (to.has_value() && (k == to.value() || to.value() < k))
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