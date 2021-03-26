// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf_assert.h"
#include "serialized.h"

#include <msgpack/msgpack.hpp>
#include <nlohmann/json.hpp>
#include <small_vector/SmallVector.h>

namespace champ
{
  using Version = uint64_t;
  using DeletableVersion = int64_t;

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
    using SerialisedEntry = llvm_vecsmall::SmallVector<uint8_t, 8>;
  }

  namespace untyped
  {
    using SerialisedEntry = champ::serialisers::SerialisedEntry;
    using VersionV = champ::VersionV<SerialisedEntry>;
  }

  template <class T>
  inline size_t get_size(const T& data)
  {
    return sizeof(uint64_t) + sizeof(data);
  }

  template <>
  inline size_t get_size<champ::untyped::SerialisedEntry>(
    const champ::untyped::SerialisedEntry& data)
  {
    return sizeof(uint64_t) + data.size();
  }

  template <>
  inline size_t get_size<champ::untyped::VersionV>(
    const champ::untyped::VersionV& data)
  {
    return sizeof(uint64_t) + sizeof(data.version) + data.value.size();
  }

  template <class T>
  inline size_t serialize(const T& t, uint8_t*& data, size_t& size)
  {
    uint64_t data_size = sizeof(T);
    serialized::write(
      data,
      size,
      reinterpret_cast<const uint8_t*>(&data_size),
      sizeof(uint64_t));
    serialized::write(
      data, size, reinterpret_cast<const uint8_t*>(&t), sizeof(T));
    return sizeof(uint64_t) + sizeof(T);
  }

  template <>
  inline size_t serialize<champ::untyped::SerialisedEntry>(
    const champ::untyped::SerialisedEntry& t, uint8_t*& data, size_t& size)
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
  inline size_t serialize<champ::untyped::VersionV>(
    const champ::untyped::VersionV& t, uint8_t*& data, size_t& size)
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

  template <class T>
  inline T deserialize(const uint8_t*& data, size_t& size)
  {
    size_t result = serialized::read<size_t>(data, size);
    (void)result;
    CCF_ASSERT_FMT(
      result == sizeof(T), "result:{} == sizeof(T):{}", result, sizeof(T));
    return serialized::read<T>(data, size);
  }

  template <>
  inline champ::untyped::SerialisedEntry deserialize<
    champ::untyped::SerialisedEntry>(const uint8_t*& data, size_t& size)
  {
    uint64_t data_size = serialized::read<uint64_t>(data, size);
    champ::untyped::SerialisedEntry ret;
    ret.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }

  template <>
  inline champ::untyped::VersionV deserialize<champ::untyped::VersionV>(
    const uint8_t*& data, size_t& size)
  {
    champ::untyped::VersionV ret;
    uint64_t data_size = serialized::read<uint64_t>(data, size);
    champ::Version version = serialized::read<champ::Version>(data, size);
    ret.version = version;
    data_size -= sizeof(champ::Version);
    ret.value.append(data, data + data_size);
    serialized::skip(data, size, data_size);
    return ret;
  }
}