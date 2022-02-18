// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/byte_vector.h"

// #include "ds/hash.h"
// #include "kv/kv_types.h"
#ifndef KV_STATE_RB
#  include "ds/champ_map.h"
#else
#  include "ds/rb_map.h"
#endif

#include <map>

namespace kv::untyped
{
  using SerialisedEntry = ccf::ByteVector;
  using SerialisedKeyHasher = std::hash<SerialisedEntry>;

  using K = SerialisedEntry;
  using V = SerialisedEntry;
  using H = SerialisedKeyHasher;

  using VersionV = map::VersionV<V>;

#ifndef KV_STATE_RB
  using State = champ::Map<K, VersionV<V>, H>;
#else
  using State = rb::Map<K, VersionV<V>>;
#endif

  // This is a map of keys and with a tuple of the key's write version and
  // the
  // version of last transaction which read the key and committed successfully
  using LastReadVersion = Version;
  using Read = std::map<K, std::tuple<DeletableVersion, LastReadVersion>>;

  // nullopt values represent deletions
  using Write = std::map<K, std::optional<V>>;

  // This is a container for a write-set + dependencies. It can be applied to a
  // given state, or used to track a set of operations on a state
  struct ChangeSet : public AbstractChangeSet
  {
  protected:
    ChangeSet() {}

  public:
    const size_t rollback_counter = {};
    const kv::untyped::State state = {};
    const kv::untyped::State committed = {};
    const Version start_version = {};

    Version read_version = NoVersion;
    kv::untyped::Read reads = {};
    kv::untyped::Write writes = {};

    ChangeSet(
      size_t rollbacks,
      kv::untyped::State& current_state,
      kv::untyped::State& committed_state,
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

  using ChangeSetPtr = std::unique_ptr<ChangeSet>;

  // This is a container for a snapshot. It has no dependencies as the snapshot
  // obliterates the current state.
  struct SnapshotChangeSet : public ChangeSet
  {
    const kv::untyped::State state;
    const Version version;

    SnapshotChangeSet(kv::untyped::State&& snapshot_state, Version version_) :
      state(std::move(snapshot_state)),
      version(version_)
    {}

    SnapshotChangeSet(SnapshotChangeSet&) = delete;

    bool has_writes() const override
    {
      return true;
    }
  };

  // TODO: Delete? Move to a separate header?
  // /// Signature for transaction commit handlers
  // template <typename W>
  // using CommitHook = std::function<void(Version, const W&)>;

  // template <typename W>
  // using MapHook =
  //   std::function<std::unique_ptr<ConsensusHook>(Version, const W&)>;
}