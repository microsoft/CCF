// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/map.h"
#include "kv/serialised_entry.h"

#include <msgpack/msgpack.hpp>

namespace tpcc
{
  using Bytes = kv::serialisers::SerialisedEntry;

  namespace detail
  {
    struct SerialisedEntryWriter
    {
      Bytes& entry;

      void write(const char* d, size_t n)
      {
        entry.insert(entry.end(), d, d + n);
      }
    };
  }

  template <typename T>
  struct MsgPackSerialiser
  {
    static Bytes to_serialised(const T& t)
    {
      Bytes e;
      detail::SerialisedEntryWriter w{e};
      msgpack::pack(w, t);
      return e;
    }

    static T from_serialised(const Bytes& rep)
    {
      msgpack::object_handle oh =
        msgpack::unpack(reinterpret_cast<const char*>(rep.data()), rep.size());
      auto object = oh.get();
      return object.as<T>();
    }
  };
}