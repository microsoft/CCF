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

    // Number of bytes to reserve initially for storage of transaction frame
    static constexpr size_t initial_reserve_size = 72;

    WriterData buf;

    template <typename T>
    void serialise_entry(const T& entry)
    {
      buf.insert(buf.end(), entry.begin(), entry.end());
    }

    template <typename T>
    void serialise_entry(T&& entry)
    {
      buf.insert(
        buf.end(),
        std::make_move_iterator(entry.begin()),
        std::make_move_iterator(entry.end()));
    }

    void serialise_size(size_t size)
    {
      WriterData size_entry(sizeof(size_t));
      auto data_ = size_entry.data();
      auto size_ = size_entry.size();
      serialized::write(data_, size_, size);

      serialise_entry(std::move(size_entry));
    }

  public:
    RawWriter()
    {
      buf.reserve(initial_reserve_size);
    }

    template <typename T>
    void append(T&& t)
    {
      WriterData entry(sizeof(T));
      auto data_ = entry.data();
      auto size_ = entry.size();
      serialized::write(data_, size_, t);

      serialise_entry(std::move(entry));
    }

    template <typename T>
    void append_pre_serialised(const T& entry)
    {
      serialise_size(entry.size());
      if (entry.size() > 0)
      {
        serialise_entry(entry);
      }
    }

    void clear()
    {
      buf.clear();
    }

    WriterData get_raw_data()
    {
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
      auto remainder = data_size - data_offset;
      auto data = data_ptr + data_offset;
      T t = serialized::read<T>(data, remainder);

      const auto bytes_read = data_size - data_offset - remainder;
      data_offset += bytes_read;
      return t;
    }

    template <typename T>
    T read_next_pre_serialised()
    {
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
