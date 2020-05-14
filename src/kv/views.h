// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "map.h"

#include <functional>
#include <map>

namespace kv
{
  // When a collection of Maps are locked, the locks must be acquired in a
  // stable order to avoid deadlocks. This ordered map will claim in name-order
  template <class S, class D>
  using OrderedViews = std::map<std::string, MapView<S, D>>;

  template <typename SP, typename DP>
  static inline std::
    map<kv::SecurityDomain, std::vector<AbstractTxView<SP, DP>*>>
    get_maps_grouped_by_domain(const OrderedViews<SP, DP>& maps)
  {
    std::map<kv::SecurityDomain, std::vector<AbstractTxView<SP, DP>*>>
      grouped_maps;
    for (auto it = maps.cbegin(); it != maps.cend(); ++it)
    {
      grouped_maps[it->second.map->get_security_domain()].push_back(
        it->second.view.get());
    }
    return grouped_maps;
  }

  template <class S, class D>
  struct ViewContainer
  {
    virtual ~ViewContainer() = default;
    virtual void set_view_list(OrderedViews<S, D>& view_list) = 0;
  };

  // Atomically checks for conflicts then applies the writes in a set of views
  // to their underlying Maps. Calls f() at most once, iff the writes are
  // applied, to retrieve a unique Version for the write set.
  template <class S, class D>
  static inline std::optional<Version> apply_views(
    OrderedViews<S, D>& views, std::function<Version()> f)
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
    }

    if (ok && has_writes)
    {
      // Get the version number to be used for this commit.
      version = f();

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