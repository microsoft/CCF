// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/msgpack_adaptor_nlohmann.h"
#include "../ds/serialized.h"
#include "generic_serialise_wrapper.h"
#include "kv_types.h"

#include <iterator>
#include <msgpack/msgpack.hpp>
#include <nlohmann/json.hpp>
#include <sstream>
#include <type_traits>

MSGPACK_ADD_ENUM(kv::KvOperationType);
MSGPACK_ADD_ENUM(kv::SecurityDomain);

namespace kv
{
  class MsgPackWriter;
  template <typename W>
  class GenericSerialiseWrapper;
  using KvStoreSerialiser = GenericSerialiseWrapper<MsgPackWriter>;

  class MsgPackReader;
  template <typename W>
  class GenericDeserialiseWrapper;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<MsgPackReader>;

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
}
