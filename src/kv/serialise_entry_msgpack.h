// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "serialised_entry.h"

#include <msgpack/msgpack.hpp>

namespace kv::serialisers
{
  template <typename T>
  struct MsgPackSerialiser
  {
    static SerialisedEntry to_serialised(const T& t)
    {
      msgpack::sbuffer sb;
      msgpack::pack(sb, t);
      auto sb_data = reinterpret_cast<const uint8_t*>(sb.data());
      return SerialisedEntry(sb_data, sb_data + sb.size());
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