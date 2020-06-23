#pragma once

#include "ccf_assert.h"
#include "serialized.h"

#include <msgpack/msgpack.hpp>
#include <nlohmann/json.hpp>
#include <small_vector/SmallVector.h>

namespace kv
{
  using Version = int64_t;

  template <typename V>
  struct VersionV
  {
    Version version;
    V value;

    VersionV() = default;
    VersionV(Version ver, V val) : version(ver), value(val) {}
  };

  namespace serialisers
  {
    using SerialisedEntry = llvm_vecsmall::SmallVector<uint8_t, 8>;
  }

  namespace untyped
  {
    using SerialisedEntry = kv::serialisers::SerialisedEntry;
    using VersionV = kv::VersionV<SerialisedEntry>;
  }
}

namespace champ
{
  template <class T>
  inline size_t get_size(const T& data)
  {
    return sizeof(uint64_t) + sizeof(T);
  }

  template <>
  inline size_t get_size<kv::untyped::SerialisedEntry>(
    const kv::untyped::SerialisedEntry& data)
  {
    return sizeof(uint64_t) + data.size();
  }

  template <>
  inline size_t get_size<kv::untyped::VersionV>(
    const kv::untyped::VersionV& data)
  {
    return sizeof(uint64_t) + sizeof(data.version) + data.value.size();
  }

  template <class T>
  inline size_t serialize(const T& t, uint8_t*& data, size_t& size)
  {
    uint64_t data_size = sizeof(T);
    serialized::write(
      data, size, reinterpret_cast<const uint8_t*>(&data_size), sizeof(T));
    serialized::write(
      data, size, reinterpret_cast<const uint8_t*>(&t), sizeof(T));
    return sizeof(uint64_t) + sizeof(T);
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

  template <class T>
  inline T deserialize(const uint8_t*& data, size_t& size)
  {
    size_t result = serialized::read<size_t>(data, size);
    CCF_ASSERT_FMT(
      result == sizeof(T), "result:{} == sizeof(T):{}", result, sizeof(T));
    return serialized::read<T>(data, size);
  }

  template <>
  inline kv::untyped::SerialisedEntry deserialize<kv::untyped::SerialisedEntry>(
    const uint8_t*& data, size_t& size)
  {
    uint64_t data_size = serialized::read<uint64_t>(data, size);
    kv::untyped::SerialisedEntry ret;
    ret.assign(data_size, *data);
    serialized::skip(data, size, data_size);
    return ret;
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
    ret.value.assign(data_size, *data);
    serialized::skip(data, size, data_size);
    return ret;
  }
}