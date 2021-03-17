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

    // Where we have pre-serialised data, we dump it length-prefixed into the
    // output buffer. If we call append, then pack will prefix the data with
    // some type information, potentially redundantly repacking already-packed
    // data. This means the output is no longer a stream of msgpack objects!
    // Parsers are expected to know the type of the Ks and Vs for the tables
    // they care about, and skip over any others
    template <typename T>
    void append_pre_serialised(const T& entry)
    {
      const uint64_t size = entry.size();
      sb.write(reinterpret_cast<char const*>(&size), sizeof(size));
      if (entry.size() > 0)
      {
        sb.write(reinterpret_cast<char const*>(entry.data()), entry.size());
      }
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
    T read_next_pre_serialised()
    {
      auto remainder = data_size - data_offset;
      auto data = reinterpret_cast<const uint8_t*>(data_ptr + data_offset);
      const auto entry_size = serialized::read<uint64_t>(data, remainder);

      if (remainder < entry_size)
      {
        throw std::runtime_error(fmt::format(
          "Expected {} byte entry, found only {}", entry_size, remainder));
      }

      const auto bytes_read = data_size - data_offset - remainder;
      data_offset += bytes_read;

      const auto before_offset = data_offset;
      data_offset += entry_size;
      return {data_ptr + before_offset, data_ptr + data_offset};
    }

    bool is_eos()
    {
      return data_offset >= data_size;
    }
  };
}
