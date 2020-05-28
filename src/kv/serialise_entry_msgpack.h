// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <msgpack/msgpack.hpp>
#include <vector>

namespace kv::serialisers
{
  template <typename T>
  struct MsgPackSerialiser
  {
    using Bytes = std::vector<uint8_t>;

    static Bytes to_serialised(const T& t)
    {
      msgpack::sbuffer sb;
      msgpack::pack(sb, t);
      auto sb_data = reinterpret_cast<const uint8_t*>(sb.data());
      return Bytes(sb_data, sb_data + sb.size());
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