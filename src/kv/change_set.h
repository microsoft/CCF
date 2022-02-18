// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/hash.h"
#include "kv/kv_types.h"
#ifndef KV_STATE_RB
#  include "ds/champ_map.h"
#else
#  include "ds/rb_map.h"
#endif

// TODO: Temp
#include "kv/untyped_change_set.h"
#include "kv/version_v.h"

#include <map>

namespace kv
{
  template <typename K, typename V, typename H>
#ifndef KV_STATE_RB
  using State = champ::Map<K, VersionV<V>, H>;
#else
  using State = rb::Map<K, VersionV<V>>;
#endif

  template <typename K, typename V, typename H>
  using Snapshot = typename State<K, V, H>::Snapshot;

  // This is a map of keys and with a tuple of the key's write version and the
  // version of last transaction which read the key and committed successfully
  using LastReadVersion = Version;
  template <typename K>
  using Read = std::map<K, std::tuple<DeletableVersion, LastReadVersion>>;

  // nullopt values represent deletions
  template <typename K, typename V>
  using Write = std::map<K, std::optional<V>>;

  /// Signature for transaction commit handlers
  template <typename W>
  using CommitHook = std::function<void(Version, const W&)>;

  template <typename W>
  using MapHook =
    std::function<std::unique_ptr<ConsensusHook>(Version, const W&)>;
}