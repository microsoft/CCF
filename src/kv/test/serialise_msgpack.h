// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/map.h"
#include "kv/serialised_entry.h"

#include <msgpack/msgpack.hpp>

namespace kv::serialisers
{
  namespace detail
  {
    struct SerialisedEntryWriter
    {
      SerialisedEntry& entry;

      void write(const char* d, size_t n)
      {
        entry.insert(entry.end(), d, d + n);
      }
    };
  }

  template <typename T>
  struct MsgPackSerialiser
  {
    static SerialisedEntry to_serialised(const T& t)
    {
      SerialisedEntry e;
      detail::SerialisedEntryWriter w{e};
      msgpack::pack(w, t);
      return e;
    }

    static T from_serialised(const SerialisedEntry& rep)
    {
      msgpack::object_handle oh =
        msgpack::unpack(reinterpret_cast<const char*>(rep.data()), rep.size());
      auto object = oh.get();
      return object.as<T>();
    }
  };
}

namespace kv
{
  template <typename K, typename V>
  using MsgPackSerialisedMap =
    MapSerialisedWith<K, V, kv::serialisers::MsgPackSerialiser>;
}