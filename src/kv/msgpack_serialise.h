// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/msgpack_adaptor_nlohmann.h"
#include "ds/serialized.h"
#include "generic_serialise_wrapper.h"
#include "serialised_entry.h"

#include <iterator>
#include <msgpack/msgpack.hpp>
#include <nlohmann/json.hpp>
#include <sstream>
#include <type_traits>

MSGPACK_ADD_ENUM(kv::KvOperationType);
MSGPACK_ADD_ENUM(kv::SecurityDomain);

namespace kv
{
  class MsgPackWriter
  {
  private:
    msgpack::sbuffer sb;

  public:
    template <typename T>
    void append(T&& t)
    {
      msgpack::pack(sb, std::forward<T>(t));
    }

    // Where we have pre-serialised data, we dump it directly into the output
    // buffer. If we call append, then pack will prefix the data with some type
    // information, potentially redundantly repacking already-packed data.
    void append_raw(const kv::serialisers::SerialisedEntry& entry)
    {
      const auto size = entry.size();
      sb.write(reinterpret_cast<char const*>(&size), sizeof(size));
      sb.write(reinterpret_cast<char const*>(entry.data()), size);
    }

    void clear()
    {
      sb.clear();
    }

    bool is_empty()
    {
      return sb.size() == 0;
    }

    std::vector<uint8_t> get_raw_data()
    {
      return {reinterpret_cast<uint8_t*>(sb.data()),
              reinterpret_cast<uint8_t*>(sb.data()) + sb.size()};
    }
  };

  class MsgPackReader
  {
  public:
    const char* data_ptr;
    size_t data_offset;
    size_t data_size;
    msgpack::object_handle msg;

  public:
    MsgPackReader(const MsgPackReader& other) = delete;
    MsgPackReader& operator=(const MsgPackReader& other) = delete;

    MsgPackReader(const uint8_t* data_in_ptr = nullptr, size_t data_in_size = 0)
    {
      init(data_in_ptr, data_in_size);
    }

    void init(const uint8_t* data_in_ptr, size_t data_in_size)
    {
      data_offset = 0;
      data_ptr = (const char*)data_in_ptr;
      data_size = data_in_size;
    }

    template <typename T>
    T read_next()
    {
      msgpack::unpack(msg, data_ptr, data_size, data_offset);
      return msg->as<T>();
    }

    kv::serialisers::SerialisedEntry read_next_raw()
    {
      const auto size_size = sizeof(size_t);
      if (data_size - data_offset < size_size)
      {
        throw msgpack::insufficient_bytes("insufficient bytes A");
      }
      size_t size = *reinterpret_cast<const size_t*>(data_ptr + data_offset);
      data_offset += size_size;

      if (data_size - data_offset < size)
      {
        throw msgpack::insufficient_bytes("insufficient bytes B");
      }

      auto entry_data =
        reinterpret_cast<const uint8_t*>(data_ptr + data_offset);
      data_offset += size;
      return kv::serialisers::SerialisedEntry(entry_data, entry_data + size);
    }

    template <typename T>
    T peek_next()
    {
      auto before_offset = data_offset;
      msgpack::unpack(msg, data_ptr, data_size, data_offset);
      data_offset = before_offset;
      return msg->as<T>();
    }

    bool is_eos()
    {
      return data_offset >= data_size;
    }
  };

  using KvStoreSerialiser = GenericSerialiseWrapper<MsgPackWriter>;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<MsgPackReader>;
}
