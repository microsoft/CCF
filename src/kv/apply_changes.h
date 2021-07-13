// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "kv_types.h"
#include "untyped_map_handle.h"

#include <functional>
#include <map>

namespace kv
{
  // All collections of Map must be ordered so that we lock their contained
  // maps in a stable order. The order here is by map name
  using MapCollection = std::map<std::string, std::shared_ptr<AbstractMap>>;

  struct AbstractChangeContainer
  {
    virtual ~AbstractChangeContainer() = default;
    virtual void set_change_list(OrderedChanges&& change_list, Term term) = 0;
  };

  // Atomically checks for conflicts then applies the writes in the given change
  // sets to their underlying Maps. Calls f() at most once, iff the writes are
  // applied, to retrieve a unique Version for the write set and return the max
  // version which can have a conflict with the transaction.
  //
  // The track_read_versions parameter tells the store if it needs to track the
  // last read version for every key. This is required for backup execution as
  // described at the top of tx.h

  using VersionLastNewMap = Version;
  using VersionResolver = std::function<std::tuple<Version, VersionLastNewMap>(
    bool tx_contains_new_map)>;

  static inline std::optional<std::tuple<Version, Version>> apply_changes(
    OrderedChanges& changes,
    VersionResolver version_resolver_fn,
    kv::ConsensusHookPtrs& hooks,
    const MapCollection& new_maps = {},
    const std::optional<Version>& new_maps_conflict_version = std::nullopt,
    bool track_read_versions = false)
  {
    // All maps with pending writes are locked, transactions are prepared
    // and possibly committed, and then all maps with pending writes are
    // unlocked. This is to prevent transactions from being committed in an
    // interleaved fashion.
    Version version = NoVersion;
    bool has_writes = false;
    kv::Version max_conflict_version = 0;

    std::map<std::string, std::unique_ptr<AbstractCommitter>> views;
    for (const auto& [map_name, mc] : changes)
    {
      views[map_name] = mc.map->create_committer(mc.changeset.get());
    }

    for (auto it = changes.begin(); it != changes.end(); ++it)
    {
      bool changeset_has_writes = it->second.changeset->has_writes();
      if (changeset_has_writes)
      {
        has_writes = true;
      }
      if (changeset_has_writes || track_read_versions)
      {
        it->second.map->lock();
      }
    }

    bool ok = true;
    bool set_max_conflict_version_to_version = false;
    for (auto it = views.begin(); it != views.end(); ++it)
    {
      if (!it->second->prepare(track_read_versions, max_conflict_version))
      {
        ok = false;
        break;
      }
      if (max_conflict_version == kv::NoVersion)
      {
        set_max_conflict_version_to_version = true;
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
      auto store = map_ptr->get_store();

      // This is to avoid recursively locking version_lock by calling
      // current_version() in the commit_reserved case.
      kv::Version current_v;
      if (new_maps_conflict_version.has_value())
      {
        current_v = *new_maps_conflict_version;
      }
      else
      {
        current_v = store->current_version();
      }

      if (store->get_map(current_v, map_name) != nullptr)
      {
        ok = false;
        break;
      }
    }

    if (ok && has_writes)
    {
      // Get the version number to be used for this commit.
      kv::Version version_last_new_map;
      std::tie(version, version_last_new_map) =
        version_resolver_fn(!new_maps.empty());
      max_conflict_version =
        std::max(max_conflict_version, version_last_new_map);

      if (version > max_conflict_version || !track_read_versions)
      {
        // Since the tracking of a read version is done in the key-value pair it
        // is not possible to track the dependencies of two transactions that
        // depend on a key-value pair on a map that does not exist yet.
        // Thus, execution is gated on map creation.
        //
        // Additionally, if the prepare set max_conflict_version to NoVersion
        // then the max_conflict_version is set to version - 1 once the
        // transaction's version has been obtained.
        if (
          track_read_versions &&
          ((!new_maps.empty() && version > 0) ||
           set_max_conflict_version_to_version))
        {
          max_conflict_version = version - 1;
        }

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

        for (auto it = views.begin(); it != views.end(); ++it)
        {
          it->second->commit(version, track_read_versions);
        }

        // Collect ConsensusHooks
        for (auto it = views.begin(); it != views.end(); ++it)
        {
          auto hook_ptr = it->second->post_commit();
          if (hook_ptr != nullptr)
          {
            hooks.push_back(std::move(hook_ptr));
          }
        }
      }
      else
      {
        // A linearizability violation was detected
        ok = false;
      }
    }

    for (auto it = changes.begin(); it != changes.end(); ++it)
    {
      if (it->second.changeset->has_writes() || track_read_versions)
      {
        it->second.map->unlock();
      }
    }

    if (!ok)
    {
      return std::nullopt;
    }

    return std::make_tuple(version, max_conflict_version);
  }
}