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
    using WriterData = kv::serialisers::SerialisedEntry;

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
    RawWriter() = default;

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
    void append_vector(const std::vector<T>& vec)
    {
      size_t vec_size = sizeof(T) * vec.size();
      serialise_size(vec_size);

      WriterData data(vec_size);
      auto data_ = data.data();
      auto size_ = data.size();
      serialized::write(
        data_, size_, reinterpret_cast<const uint8_t*>(vec.data()), vec_size);

      serialise_entry(std::move(data));
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

    std::vector<uint8_t> get_raw_data()
    {
      return {buf.data(), buf.data() + buf.size()};
    }
  };

  class RawReader
  {
  public:
    const uint8_t* data_ptr;
    size_t data_offset;
    size_t data_size;

    /** Reads the next entry, advancing data_offset
     */
    template <typename T>
    T read_entry()
    {
      auto remainder = data_size - data_offset;
      auto data = data_ptr + data_offset;
      const auto entry = serialized::read<T>(data, remainder);
      const auto bytes_read = data_size - data_offset - remainder;
      data_offset += bytes_read;
      return entry;
    }

    /** Reads the next size-prefixed entry
     */
    size_t read_size_prefixed_entry(size_t& start_offset)
    {
      auto remainder = data_size - data_offset;
      auto entry_size = read_entry<size_t>();

      if (remainder < entry_size)
      {
        throw std::runtime_error(fmt::format(
          "Expected {} byte entry, found only {}", entry_size, remainder));
      }

      start_offset = data_offset;
      data_offset += entry_size;

      return entry_size;
    }

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
      return read_entry<T>();
    }

    template <typename T>
    std::vector<T> read_next_vector()
    {
      size_t entry_offset = 0;
      size_t entry_size = read_size_prefixed_entry(entry_offset);

      std::vector<T> vec(entry_size / sizeof(T));
      auto data_ = reinterpret_cast<uint8_t*>(vec.data());
      auto size_ = entry_size;
      serialized::write(data_, size_, data_ptr + entry_offset, entry_size);

      return vec;
    }

    template <typename T>
    T read_next_pre_serialised()
    {
      size_t entry_offset = 0;
      read_size_prefixed_entry(entry_offset);

      return {data_ptr + entry_offset, data_ptr + data_offset};
    }

    bool is_eos()
    {
      return data_offset >= data_size;
    }
  };

  using KvStoreSerialiser = GenericSerialiseWrapper<RawWriter>;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<RawReader>;
}
