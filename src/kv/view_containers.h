// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"

#include <functional>
#include <map>

namespace kv
{
  struct MapView
  {
    // Weak pointer to source map
    AbstractMap* map;

    // Owning pointer of TxView over that map
    std::unique_ptr<AbstractTxView> view;
  };

  // When a collection of Maps are locked, the locks must be acquired in a
  // stable order to avoid deadlocks. This ordered map will claim in name-order
  using OrderedViews = std::map<std::string, MapView>;

  // All collections of Map must be ordered so that we lock their contained
  // maps in a stable order. The order here is by map name
  using MapCollection = std::map<std::string, std::shared_ptr<AbstractMap>>;

  struct AbstractViewContainer
  {
    virtual ~AbstractViewContainer() = default;
    virtual void set_view_list(OrderedViews& view_list, Term term) = 0;
  };

  // Atomically checks for conflicts then applies the writes in a set of views
  // to their underlying Maps. Calls f() at most once, iff the writes are
  // applied, to retrieve a unique Version for the write set.
  static inline std::optional<Version> apply_views(
    OrderedViews& views,
    std::function<Version()> f,
    const MapCollection& new_maps = {})
  {
    // All maps with pending writes are locked, transactions are prepared
    // and possibly committed, and then all maps with pending writes are
    // unlocked. This is to prevent transactions from being committed in an
    // interleaved fashion.
    Version version = 0;
    bool has_writes = false;

    for (auto it = views.begin(); it != views.end(); ++it)
    {
      if (it->second.view->has_writes())
      {
        it->second.map->lock();
        has_writes = true;
      }
    }

    bool ok = true;

    for (auto it = views.begin(); it != views.end(); ++it)
    {
      if (!it->second.view->prepare())
      {
        ok = false;
        break;
      }

      for (const auto& [map_name, map_ptr] : new_maps)
      {
        // Check that none of these pending maps have already been created.
        // It is possible for non-conflicting other transactions to commit here
        // and increment the version, so we may ask this question at different
        // versions. This is fine - none can create maps (ie - change their
        // conflict set with this operation) while we hold the store lock. Assume that the caller is currently holding store->lock()
        auto store = map_ptr->get_store();
        if (store->get_map(store->current_version(), map_name) != nullptr)
        {
          ok = false;
          break;
        }
      }
    }

    if (ok && has_writes)
    {
      // Get the version number to be used for this commit.
      version = f();

      // Transfer ownership of these new maps to their target stores, iff we
      // have writes to them
      for (const auto& [map_name, map_ptr] : new_maps)
      {
        const auto it = views.find(map_name);
        if (it != views.end() && it->second.view->has_writes())
          map_ptr->get_store()->add_dynamic_map(version, map_ptr);
      }

      for (auto it = views.begin(); it != views.end(); ++it)
        it->second.view->commit(version);

      for (auto it = views.begin(); it != views.end(); ++it)
        it->second.view->post_commit();
    }

    for (auto it = views.begin(); it != views.end(); ++it)
    {
      if (it->second.view->has_writes())
        it->second.map->unlock();
    }

    if (!ok)
      return std::nullopt;

    return version;
  }
}