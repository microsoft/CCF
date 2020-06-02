// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <msgpack/msgpack.hpp>
#include <nlohmann/json.hpp>
#include <small_vector/SmallVector.h>

namespace kv::serialisers
{
  using SerialisedEntry = llvm_vecsmall::SmallVector<uint8_t, 64>;
}

// TODO: We should never actually be doing this!
namespace msgpack
{
  MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
  {
    namespace adaptor
    {
      template <>
      struct pack<kv::serialisers::SerialisedEntry>
      {
        template <typename Stream>
        msgpack::packer<Stream>& operator()(
          msgpack::packer<Stream>& o,
          const kv::serialisers::SerialisedEntry& entry) const
        {
          o.pack_bin(entry.size());
          o.pack_bin_body(
            reinterpret_cast<const char*>(entry.data()), entry.size());

          return o;
        }
      };

      template <>
      struct convert<kv::serialisers::SerialisedEntry>
      {
        const msgpack::object& operator()(
          const msgpack::object& o,
          kv::serialisers::SerialisedEntry& entry) const
        {
          if ((o.type) != msgpack::type::BIN)
          {
            throw msgpack::type_error();
          }

          entry = kv::serialisers::SerialisedEntry(
            o.via.bin.ptr, o.via.bin.ptr + o.via.bin.size);

          return o;
        }
      };
    }
  }
}
