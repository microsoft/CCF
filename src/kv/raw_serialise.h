// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"
#include "generic_serialise_wrapper.h"
#include "serialised_entry.h"

#include <iterator>
#include <sstream>
#include <type_traits>

namespace kv
{
  class RawWriter
  {
  private:
    using WriterData = std::vector<uint8_t>;

    WriterData buf;
    uint8_t* data = nullptr;
    size_t size = 0;

  public:
    RawWriter()
    {
      // Reserve
      buf.reserve(72);
      // size = 1000;
      // buf.resize(size);
      // data = buf.data();
    }

    template <typename T>
    void append(T&& t)
    {
      const auto data = reinterpret_cast<const uint8_t*>(&t);
      WriterData entry = {data, data + sizeof(T)};
      buf.insert(
        buf.end(),
        std::make_move_iterator(entry.begin()),
        std::make_move_iterator(entry.end()));
      LOG_FAIL_FMT("Offset: {}", buf.size());
      LOG_FAIL_FMT("Buf is now of capacity: {}", buf.capacity());
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
      //   const uint64_t size = entry.size();
      //   sb.write(reinterpret_cast<char const*>(&size), sizeof(size));
      // serialized::write(data, size, entry.size());
      // buf.push_back(entry.size());
      auto entry_size = entry.size();
      const auto size_ = reinterpret_cast<const uint8_t*>(&entry_size);
      WriterData size = {size_, size_ + sizeof(size_t)};
      buf.insert(
        buf.end(),
        std::make_move_iterator(size.begin()),
        std::make_move_iterator(size.end()));
      if (entry.size() > 0)
      {
        buf.insert(
          buf.end(),
          std::make_move_iterator(entry.begin()),
          std::make_move_iterator(entry.end()));
        LOG_FAIL_FMT("Offset: {}", buf.size());
        // TODO: Remove
        // buf.emplace_back(std::move(entry));
      }
      // buf.emplace_back(entry.size());
      // if (entry.size() > 0)
      // {
      //   buf.emplace_back(entry);
      //   // serialized::write(data, size, entry.data(), entry.size());
      //   // sb.write(reinterpret_cast<char const*>(entry.data()),
      //   entry.size());
      // }
    }

    void clear()
    {
      buf.clear();
    }

    WriterData get_raw_data()
    {
      LOG_FAIL_FMT("Capacity at the end {}", buf.capacity());
      LOG_FAIL_FMT("Serialised data of size {}", buf.size());
      return buf;
    }
  };

  class RawReader
  {
  public:
    const uint8_t* data_ptr;
    size_t data_offset;
    size_t data_size;

  public:
    RawReader(const RawReader& other) = delete;
    RawReader& operator=(const RawReader& other) = delete;

    RawReader(const uint8_t* data_in_ptr = nullptr, size_t data_in_size = 0)
    {
      init(data_in_ptr, data_in_size);
    }

    void init(const uint8_t* data_in_ptr, size_t data_in_size)
    {
      data_offset = 0;
      data_ptr = data_in_ptr;
      data_size = data_in_size;
    }

    template <typename T>
    T read_next()
    {
      LOG_FAIL_FMT("Read next, offset: {}", data_offset);

      // TODO: Check for reading past the end!
      auto data_ = data_ptr + data_offset;
      auto size_ = data_size - data_offset;
      T t = serialized::read<T>(data_, size_);
      data_offset += data_ - (data_ptr + data_offset);
      LOG_FAIL_FMT("Offset is now {}", data_offset);
      return t;
    }

    template <typename T>
    T read_next_pre_serialised()
    {
      LOG_FAIL_FMT("Read next pre serialised: {}", data_offset);
      auto remainder = data_size - data_offset;
      auto data = reinterpret_cast<const uint8_t*>(data_ptr + data_offset);
      const auto entry_size = serialized::read<size_t>(data, remainder);

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

  using KvStoreSerialiser = GenericSerialiseWrapper<RawWriter>;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<RawReader>;
}
