// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/champ_map.h"
#include "ds/hash.h"
#include "kv/kv_types.h"

#include <map>

namespace kv
{
  template <typename V>
  struct VersionV
  {
    Version version;
    V value;

    VersionV() = default;
    VersionV(Version ver, V val) : version(ver), value(val) {}
  };

  template <typename K, typename V, typename H, typename k_size, typename v_size>
  using State = champ::Map<K, VersionV<V>, H, k_size, v_size>;

  template <typename K>
  using Read = std::map<K, Version>;

  // nullopt values represent deletions
  template <typename K, typename V>
  using Write = std::map<K, std::optional<V>>;

  // This is a container for a write-set + dependencies. It can be applied to a
  // given state, or used to track a set of operations on a state
  template <typename K, typename V, typename H, typename k_size, typename v_size>
  struct ChangeSet
  {
  public:
    State<K, V, H, k_size, v_size> state;
    State<K, V, H, k_size, v_size> committed;
    Version start_version;

    Version read_version = NoVersion;
    Read<K> reads = {};
    Write<K, V> writes = {};

    ChangeSet(
      State<K, V, H, k_size, v_size>& current_state,
      State<K, V, H, k_size, v_size>& committed_state,
      Version current_version) :
      state(current_state),
      committed(committed_state),
      start_version(current_version)
    {}

    ChangeSet(ChangeSet&) = delete;
  };

  /// Signature for transaction commit handlers
  template <typename W>
  using CommitHook = std::function<void(Version, const W&)>;
}