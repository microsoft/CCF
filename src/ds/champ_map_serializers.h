#pragma once

#include <msgpack/msgpack.hpp>
#include <nlohmann/json.hpp>
#include <small_vector/SmallVector.h>

#include "serialized.h"
#include "ccf_assert.h"


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
    return sizeof(uint64_t) * 2;
  }

  template <>
  inline size_t get_size<kv::untyped::SerialisedEntry>(const kv::untyped::SerialisedEntry& data)
  {
    return sizeof(uint64_t) + data.size();
  }

  template <>
  inline size_t get_size<kv::untyped::VersionV>(const kv::untyped::VersionV& data)
  {
    return sizeof(uint64_t) + sizeof(data.version) + data.value.size();
  }
}