// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "serialized.h"

namespace map
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

  static uint32_t get_padding(uint32_t size)
  {
    uint32_t padding = size % sizeof(uintptr_t);
    if (padding != 0)
    {
      padding = sizeof(uintptr_t) - padding;
    }
    return padding;
  }

  static uint32_t add_padding(uint32_t data_size, uint8_t*& data, size_t& size)
  {
    constexpr uintptr_t padding = 0;
    uint32_t padding_size = get_padding(data_size);
    if (padding_size != 0)
    {
      serialized::write(
        data, size, reinterpret_cast<const uint8_t*>(&padding), padding_size);
    }
    return padding_size;
  }

  template <class K, class V>
  static size_t get_size_with_padding(const K& k, const V& v)
  {
    uint32_t size_k = get_size(k);
    uint32_t size_v = get_size(v);
    return size_k + get_padding(size_k) + size_v + get_padding(size_v);
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

  template <class M>
  static M deserialize_map(CBuffer serialized_state)
  {
    using KeyType = typename M::KeyType;
    using ValueType = typename M::ValueType;

    M map;
    const uint8_t* data = serialized_state.p;
    size_t size = serialized_state.rawSize();

    while (size != 0)
    {
      // Deserialize the key
      size_t key_size = size;
      KeyType key = deserialize<KeyType>(data, size);
      key_size -= size;
      serialized::skip(data, size, get_padding(key_size));

      // Deserialize the value
      size_t value_size = size;
      ValueType value = deserialize<ValueType>(data, size);
      value_size -= size;
      serialized::skip(data, size, get_padding(value_size));
      map = map.put(key, value);
    }
    return map;
  }
}