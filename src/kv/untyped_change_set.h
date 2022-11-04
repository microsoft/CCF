// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/byte_vector.h"
#include "ccf/kv/hooks.h"
#include "ccf/kv/untyped.h"
#include "kv/kv_types.h"
#include "kv/version_v.h"

#ifndef KV_STATE_RB
#  include "ds/champ_map.h"
#else
#  include "ds/rb_map.h"
#endif

namespace kv::untyped
{
  using SerialisedEntry = ccf::ByteVector;
  using SerialisedKeyHasher = std::hash<SerialisedEntry>;

  using K = SerialisedEntry;
  using V = SerialisedEntry;
  using H = SerialisedKeyHasher;

  using VersionV = kv::VersionV<V>;

#ifndef KV_STATE_RB
  using State = champ::Map<K, VersionV, H>;
#else
  using State = rb::Map<K, VersionV>;
#endif

  // This is a map of keys and with a tuple of the key's write version and
  // the version of last transaction which read the key and committed
  // successfully
  using LastReadVersion = Version;
  using Read = std::map<K, std::tuple<Version, LastReadVersion>>;

  // This is a container for a write-set + dependencies. It can be applied to
  // a given state, or used to track a set of operations on a state
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
      kv::untyped::Write changed_writes,
      Version current_version) :
      rollback_counter(rollbacks),
      state(current_state),
      committed(committed_state),
      start_version(current_version),
      writes(changed_writes)
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
}

namespace map
{
  template <>
  inline size_t get_size<kv::untyped::VersionV>(
    const kv::untyped::VersionV& data)
  {
    return sizeof(uint64_t) + sizeof(data.version) + data.value.size();
  }

  template <>
  inline size_t serialize<kv::untyped::VersionV>(
    const kv::untyped::VersionV& t, uint8_t*& data, size_t& size)
  {
    uint64_t data_size = sizeof(t.version) + t.value.size();
    serialized::write(
      data,
      size,
      reinterpret_cast<const uint8_t*>(&data_size),
      sizeof(uint64_t));
    serialized::write(
      data,
      size,
      reinterpret_cast<const uint8_t*>(&t.version),
      sizeof(t.version));
    serialized::write(
      data,
      size,
      reinterpret_cast<const uint8_t*>(t.value.data()),
      t.value.size());
    return sizeof(uint64_t) + sizeof(t.version) + t.value.size();
  }

  template <>
  inline kv::untyped::VersionV deserialize<kv::untyped::VersionV>(
    const uint8_t*& data, size_t& size)
  {
    kv::untyped::VersionV ret;
    uint64_t data_size = serialized::read<uint64_t>(data, size);
    kv::Version version = serialized::read<kv::Version>(data, size);
    ret.version = version;
    data_size -= sizeof(kv::Version);
    ret.value.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }

  template <>
  inline size_t get_size<kv::untyped::SerialisedEntry>(
    const kv::untyped::SerialisedEntry& data)
  {
    return sizeof(uint64_t) + data.size();
  }

  template <>
  inline size_t serialize<kv::untyped::SerialisedEntry>(
    const kv::untyped::SerialisedEntry& t, uint8_t*& data, size_t& size)
  {
    uint64_t data_size = t.size();
    serialized::write(
      data,
      size,
      reinterpret_cast<const uint8_t*>(&data_size),
      sizeof(uint64_t));
    serialized::write(
      data, size, reinterpret_cast<const uint8_t*>(t.data()), data_size);
    return sizeof(uint64_t) + data_size;
  }

  template <>
  inline kv::untyped::SerialisedEntry deserialize<kv::untyped::SerialisedEntry>(
    const uint8_t*& data, size_t& size)
  {
    uint64_t data_size = serialized::read<uint64_t>(data, size);
    kv::untyped::SerialisedEntry ret;
    ret.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }
}