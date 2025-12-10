// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "kv/untyped_change_set.h"
#include "kv_types.h"

#include <functional>
#include <map>

namespace ccf::kv
{
  // All collections of Map must be ordered so that we lock their contained
  // maps in a stable order. The order here is by map name
  using MapCollection = std::map<std::string, std::shared_ptr<AbstractMap>>;

  // Atomically checks for conflicts then applies the writes in the given change
  // sets to their underlying Maps. Calls f() at most once, iff the writes are
  // applied, to retrieve a unique Version for the write set and return the max
  // version which can have a conflict with the transaction.

  using VersionLastNewMap = Version;
  using VersionResolver = std::function<std::tuple<Version, VersionLastNewMap>(
    bool tx_contains_new_map)>;

  static inline std::optional<Version> apply_changes(
    OrderedChanges& changes,
    VersionResolver version_resolver_fn,
    ccf::kv::ConsensusHookPtrs& hooks,
    const MapCollection& new_maps,
    const std::optional<Version>& new_maps_conflict_version,
    bool track_deletes_on_missing_keys,
    const std::optional<Version>& expected_rollback_count = std::nullopt)
  {
    // All maps with pending writes are locked, transactions are prepared
    // and possibly committed, and then all maps with pending writes are
    // unlocked. This is to prevent transactions from being committed in an
    // interleaved fashion.
    Version version = NoVersion;
    bool has_writes = false;

    std::map<std::string, std::unique_ptr<AbstractCommitter>> views;
    for (const auto& [map_name, mc] : changes)
    {
      views[map_name] = mc.map->create_committer(mc.changeset.get());
    }

    for (auto& [map_name, mc] : changes)
    {
      has_writes |= mc.changeset->has_writes();
      mc.map->lock();
    }

    bool ok = true;

    if (expected_rollback_count.has_value() && !changes.empty())
    {
      // expected_rollback_count is only set on signature transactions
      // which always contain some writes, and on which all the maps
      // point to the same store.
      auto* store = changes.begin()->second.map->get_store();
      if (store != nullptr)
      {
        // Note that this is done when holding the lock on at least some maps
        // through the combination of the changes not being empty, and the
        // acquisition of the map locks on line 69. This guarantees atomicity
        // with respect to rollbacks, which would acquire the map lock on all
        // maps at once to truncate their roll. The net result is that the
        // transaction becomes a noop if a rollback occurred between it being
        // committed, and the side effects being applied.
        ok = store->check_rollback_count(expected_rollback_count.value());
      }
    }

    if (ok && has_writes)
    {
      for (auto& [view_name, view_ptr] : views)
      {
        if (!view_ptr->prepare())
        {
          ok = false;
          break;
        }
      }
    }

    for (const auto& [map_name, map_ptr] : new_maps)
    {
      // Check that none of these pending maps have already been created.
      // It is possible for non-conflicting other transactions to commit here
      // and increment the version, so we may ask this question at different
      // versions. This is fine - none can create maps (ie - change their
      // conflict set with this operation) while we hold the store lock. Assume
      // that the caller is currently holding store->lock()
      auto* store = map_ptr->get_store();

      // This is to avoid recursively locking version_lock by calling
      // current_version() in the commit_reserved case.
      ccf::kv::Version current_v = 0;
      if (new_maps_conflict_version.has_value())
      {
        current_v = *new_maps_conflict_version;
      }
      else
      {
        current_v = store->current_version();
      }

      if (store->get_map_unsafe(current_v, map_name) != nullptr)
      {
        ok = false;
        break;
      }
    }

    if (ok && has_writes)
    {
      // Get the version number to be used for this commit.
      ccf::kv::Version version_last_new_map = 0;
      std::tie(version, version_last_new_map) =
        version_resolver_fn(!new_maps.empty());

      // Transfer ownership of these new maps to their target stores, iff we
      // have writes to them
      for (const auto& [map_name, map_ptr] : new_maps)
      {
        const auto it = views.find(map_name);
        if (it != views.end() && it->second->has_writes())
        {
          map_ptr->get_store()->add_dynamic_map(version, map_ptr);
        }
      }

      for (auto& [view_name, view_ptr] : views)
      {
        view_ptr->commit(version, track_deletes_on_missing_keys);
      }

      // Collect ConsensusHooks
      for (auto& [view_name, view_ptr] : views)
      {
        auto hook_ptr = view_ptr->post_commit();
        if (hook_ptr != nullptr)
        {
          hooks.push_back(std::move(hook_ptr));
        }
      }
    }

    for (auto& [map_name, mc] : changes)
    {
      mc.map->unlock();
    }

    if (!ok)
    {
      return std::nullopt;
    }

    return version;
  }
}
