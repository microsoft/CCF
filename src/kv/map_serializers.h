// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/byte_vector.h"
#include "ccf/ccf_assert.h"
#include "ds/map_serializers.h"

namespace map
{
  using Version = uint64_t;
  using DeletableVersion = int64_t;

  // TODO: Where does this live? What does it do?
  template <typename V>
  struct VersionV
  {
    DeletableVersion version;
    Version read_version;
    V value;

    VersionV() :
      version(std::numeric_limits<decltype(version)>::min()),
      read_version(std::numeric_limits<decltype(read_version)>::min())
    {}
    VersionV(DeletableVersion ver, Version read_ver, V val) :
      version(ver),
      read_version(read_ver),
      value(val)
    {}
  };

  namespace serialisers
  {
    using SerialisedEntry = ccf::ByteVector;
  }

  namespace untyped
  {
    using SerialisedEntry = serialisers::SerialisedEntry;
    using VersionV = VersionV<SerialisedEntry>;
  }

  template <class T>
  inline size_t get_size(const T& data)
  {
    return sizeof(uint64_t) + sizeof(data);
  }

  template <>
  inline size_t get_size<untyped::SerialisedEntry>(
    const untyped::SerialisedEntry& data)
  {
    return sizeof(uint64_t) + data.size();
  }

  template <>
  inline size_t get_size<untyped::VersionV>(const untyped::VersionV& data)
  {
    return sizeof(uint64_t) + sizeof(data.version) + data.value.size();
  }

  template <>
  inline size_t serialize<untyped::SerialisedEntry>(
    const untyped::SerialisedEntry& t, uint8_t*& data, size_t& size)
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
  inline size_t serialize<untyped::VersionV>(
    const untyped::VersionV& t, uint8_t*& data, size_t& size)
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
  inline untyped::SerialisedEntry deserialize<untyped::SerialisedEntry>(
    const uint8_t*& data, size_t& size)
  {
    uint64_t data_size = serialized::read<uint64_t>(data, size);
    untyped::SerialisedEntry ret;
    ret.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }

  template <>
  inline untyped::VersionV deserialize<untyped::VersionV>(
    const uint8_t*& data, size_t& size)
  {
    untyped::VersionV ret;
    uint64_t data_size = serialized::read<uint64_t>(data, size);
    Version version = serialized::read<Version>(data, size);
    ret.version = version;
    data_size -= sizeof(Version);
    ret.value.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }
}