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

// Currently we have pre-serialised keys and values, which are often msgpack,
// which are then re-packed into msgpack to go into the ledger. This is
// wasteful. But without this we can't _unpack_ custom types at this level. We
// should replace this with a custom serialisation format for the ledger. This
// macro gates the intended code path.
#define MSGPACK_DONT_REPACK (0)

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
    // information, potentially redundantly repacking already-packed data. We
    // assume the serialised entry is already msgpack so we retain a consistent
    // msgpack stream. If it is in some other format, every parser will need to
    // be able to distinguish it from ths valid stream
    void append_pre_serialised(const kv::serialisers::SerialisedEntry& entry)
    {
#if MSGPACK_DONT_REPACK
      sb.write(reinterpret_cast<char const*>(entry.data()), entry.size());
#else
      append(entry);
#endif
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

    kv::serialisers::SerialisedEntry read_next_pre_serialised()
    {
#if MSGPACK_DONT_REPACK
      const auto before_offset = data_offset;
      msgpack::unpack(msg, data_ptr, data_size, data_offset);
      return kv::serialisers::SerialisedEntry(
        data_ptr + before_offset, data_ptr + data_offset);
#else
      return read_next<kv::serialisers::SerialisedEntry>();
#endif
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
