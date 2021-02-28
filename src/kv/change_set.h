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
  using VersionV = champ::VersionV<V>;
  template <typename K, typename V, typename H>
  using State = champ::Map<K, VersionV<V>, H>;
  template <typename K, typename V, typename H>
  using Snapshot = champ::Snapshot<K, VersionV<V>, H>;

  // This is a map of keys and with a tuple of the key's write version and the
  // version of last transaction which read the key and committed successfully
  using LastReadVersion = Version;
  template <typename K>
  using Read = std::map<K, std::tuple<Version, LastReadVersion>>;

  // nullopt values represent deletions
  template <typename K, typename V>
  using Write = std::map<K, std::optional<V>>;

  // This is a container for a write-set + dependencies. It can be applied to a
  // given state, or used to track a set of operations on a state
  template <typename K, typename V, typename H>
  struct ChangeSet : public AbstractChangeSet
  {
  protected:
    ChangeSet() {}

  public:
    const size_t rollback_counter = {};
    const State<K, V, H> state = {};
    const State<K, V, H> committed = {};
    const Version start_version = {};

    Version read_version = NoVersion;
    Read<K> reads = {};
    Write<K, V> writes = {};

    ChangeSet(
      size_t rollbacks,
      State<K, V, H>& current_state,
      State<K, V, H>& committed_state,
      Version current_version) :
      rollback_counter(rollbacks),
      state(current_state),
      committed(committed_state),
      start_version(current_version)
    {}

    ChangeSet(ChangeSet&) = delete;

    bool has_writes() const override
    {
      return !writes.empty();
    }
  };

  // This is a container for a snapshot. It has no dependencies as the snapshot
  // obliterates the current state.
  template <typename K, typename V, typename H>
  struct SnapshotChangeSet : public ChangeSet<K, V, H>
  {
    const State<K, V, H> state;
    const Version version;

    SnapshotChangeSet(State<K, V, H>&& snapshot_state, Version version_) :
      state(std::move(snapshot_state)),
      version(version_)
    {}

    SnapshotChangeSet(SnapshotChangeSet&) = delete;

    bool has_writes() const override
    {
      return true;
    }
  };

  /// Signature for transaction commit handlers
  template <typename W>
  using CommitHook = std::function<void(Version, const W&)>;

  template <typename W>
  using MapHook =
    std::function<std::unique_ptr<ConsensusHook>(Version, const W&)>;
}