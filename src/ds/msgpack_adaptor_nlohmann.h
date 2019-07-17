// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <msgpack-c/msgpack.hpp>
#include <nlohmann/json.hpp>

namespace msgpack
{
  MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
  {
    namespace adaptor
    {
      // Both pack and convert involve unnecessary copies. If this
      // nlohmann::json issue is accepted, we can write custom input_adapter and
      // output_adapter to read/write directly from msgpack objects.
      // https://github.com/nlohmann/json/issues/1534
      template <>
      struct pack<nlohmann::json>
      {
        template <typename Stream>
        msgpack::packer<Stream>& operator()(
          msgpack::packer<Stream>& o, const nlohmann::json& j) const
        {
          const auto packed = nlohmann::json::to_msgpack(j);

          o.pack_bin(packed.size());
          o.pack_bin_body(
            reinterpret_cast<const char*>(packed.data()), packed.size());

          return o;
        }
      };

      template <>
      struct convert<nlohmann::json>
      {
        const msgpack::object& operator()(
          const msgpack::object& o, nlohmann::json& j) const
        {
          if ((o.type) != msgpack::type::BIN)
          {
            throw msgpack::type_error();
          }

          std::vector<uint8_t> v(o.via.bin.ptr, o.via.bin.ptr + o.via.bin.size);
          j = nlohmann::json::from_msgpack(v);

          return o;
        }
      };
    }
  }
}