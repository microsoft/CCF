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

namespace ccf::kv::untyped
{
  using SerialisedEntry = ccf::ByteVector;
  using SerialisedKeyHasher = std::hash<SerialisedEntry>;

  using K = SerialisedEntry;
  using V = SerialisedEntry;
  using H = SerialisedKeyHasher;

  using VersionV = ccf::kv::VersionV<V>;

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
    ChangeSet() = default;

  public:
    const size_t rollback_counter = {};
    const ccf::kv::untyped::State state;
    const ccf::kv::untyped::State committed;
    const Version start_version = {};

    Version read_version = NoVersion;
    ccf::kv::untyped::Read reads;
    ccf::kv::untyped::Write writes;

    ChangeSet(
      size_t rollbacks,
      ccf::kv::untyped::State& current_state,
      ccf::kv::untyped::State& committed_state,
      ccf::kv::untyped::Write changed_writes,
      Version current_version) :
      rollback_counter(rollbacks),
      state(current_state),
      committed(committed_state),
      start_version(current_version),
      writes(std::move(changed_writes))
    {}

    ChangeSet(ChangeSet&) = delete;

    [[nodiscard]] bool has_writes() const override
    {
      return !writes.empty();
    }
  };

  using ChangeSetPtr = std::unique_ptr<ChangeSet>;

  // This is a container for a snapshot. It has no dependencies as the snapshot
  // obliterates the current state.
  struct SnapshotChangeSet : public ChangeSet
  {
    const ccf::kv::untyped::State state;
    const Version version;

    SnapshotChangeSet(
      ccf::kv::untyped::State&& snapshot_state, Version version_) :
      state(std::move(snapshot_state)),
      version(version_)
    {}

    SnapshotChangeSet(SnapshotChangeSet&) = delete;

    [[nodiscard]] bool has_writes() const override
    {
      return true;
    }
  };
}

namespace map
{
  template <>
  inline size_t get_size<ccf::kv::untyped::VersionV>(
    const ccf::kv::untyped::VersionV& data)
  {
    return sizeof(uint64_t) + sizeof(data.version) + data.value.size();
  }

  template <>
  inline size_t serialize<ccf::kv::untyped::VersionV>(
    const ccf::kv::untyped::VersionV& t, uint8_t*& data, size_t& size)
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
  inline ccf::kv::untyped::VersionV deserialize<ccf::kv::untyped::VersionV>(
    const uint8_t*& data, size_t& size)
  {
    ccf::kv::untyped::VersionV ret;
    auto data_size = serialized::read<uint64_t>(data, size);
    auto version = serialized::read<ccf::kv::Version>(data, size);
    ret.version = version;
    data_size -= sizeof(ccf::kv::Version);
    ret.value.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }

  template <>
  inline size_t get_size<ccf::kv::untyped::SerialisedEntry>(
    const ccf::kv::untyped::SerialisedEntry& data)
  {
    return sizeof(uint64_t) + data.size();
  }

  template <>
  inline size_t serialize<ccf::kv::untyped::SerialisedEntry>(
    const ccf::kv::untyped::SerialisedEntry& t, uint8_t*& data, size_t& size)
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
  inline ccf::kv::untyped::SerialisedEntry deserialize<
    ccf::kv::untyped::SerialisedEntry>(const uint8_t*& data, size_t& size)
  {
    auto data_size = serialized::read<uint64_t>(data, size);
    ccf::kv::untyped::SerialisedEntry ret;
    ret.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }
}