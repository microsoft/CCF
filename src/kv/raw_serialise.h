// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"
#include "generic_serialise_wrapper.h"

#include <array>
#include <small_vector/SmallVector.h>
#include <type_traits>

namespace ccf::kv
{
  class RawWriter
  {
  private:
    // Avoid heap allocations for transactions which only touch a limited number
    // of keys in a few maps
    using WriterData = llvm_vecsmall::SmallVector<uint8_t, 64>;

    WriterData buf;

    template <typename T>
    void serialise_entry(const T& t)
    {
      size_t size_before = buf.size();
      buf.resize(buf.size() + sizeof(T));

      auto data_ = buf.data() + size_before;
      auto size_ = buf.size() - size_before;
      serialized::write(data_, size_, t);
    }

    template <typename T>
    void serialise_vector(const T& entry)
    {
      size_t entry_size_bytes = sizeof(typename T::value_type) * entry.size();
      size_t size_before = buf.size();

      buf.resize(buf.size() + entry_size_bytes);

      auto data_ = buf.data() + size_before;
      auto size_ = buf.size() - size_before;
      serialized::write(
        data_,
        size_,
        reinterpret_cast<const uint8_t*>(entry.data()),
        entry_size_bytes);
    }

    template <typename T, size_t SIZE>
    void serialise_array(const std::array<T, SIZE>& array)
    {
      constexpr size_t array_size = SIZE * sizeof(T);
      size_t size_before = buf.size();
      buf.resize(buf.size() + array_size);

      auto data_ = buf.data() + size_before;
      auto size_ = buf.size() - size_before;
      serialized::write(
        data_,
        size_,
        reinterpret_cast<const uint8_t*>(array.data()),
        array_size);
    }

    void serialise_string(const std::string& str)
    {
      size_t size_before = buf.size();
      buf.resize(buf.size() + sizeof(size_t) + str.size());

      auto data_ = buf.data() + size_before;
      auto size_ = buf.size() - size_before;
      serialized::write(data_, size_, str);
    }

  public:
    RawWriter() = default;

    template <typename T>
    void append(const T& entry)
    {
      if constexpr (
        ccf::nonstd::is_std_vector<T>::value ||
        std::is_same_v<T, ccf::kv::serialisers::SerialisedEntry>)
      {
        serialise_entry(entry.size() * sizeof(typename T::value_type));
        if (entry.size() > 0)
        {
          serialise_vector(entry);
        }
      }
      else if constexpr (std::is_same_v<T, ccf::crypto::Sha256Hash>)
      {
        serialise_array(entry.h);
      }
      else if constexpr (std::is_same_v<T, EntryType>)
      {
        serialise_entry(static_cast<uint8_t>(entry));
      }
      else if constexpr (std::is_same_v<T, std::string>)
      {
        serialise_string(entry);
      }
      else if constexpr (std::is_integral_v<T>)
      {
        serialise_entry(entry);
      }
      else
      {
        static_assert(
          ccf::nonstd::dependent_false<T>::value, "Can't serialise this type");
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
      if constexpr (
        ccf::nonstd::is_std_vector<T>::value ||
        std::is_same_v<T, ccf::kv::serialisers::SerialisedEntry>)
      {
        size_t entry_offset = 0;
        size_t entry_size = read_size_prefixed_entry(entry_offset);

        T ret(entry_size / sizeof(typename T::value_type));
        auto* data_dest = reinterpret_cast<uint8_t*>(ret.data());
        auto capacity = entry_size;
        // NOLINTNEXTLINE(readability-suspicious-call-argument)
        serialized::write(
          data_dest, capacity, data_ptr + entry_offset, entry_size);

        return ret;
      }
      else if constexpr (ccf::nonstd::is_std_array<T>::value)
      {
        T ret;
        auto data_ = reinterpret_cast<uint8_t*>(ret.data());
        constexpr size_t size = ret.size() * sizeof(typename T::value_type);
        auto size_ = size;
        serialized::write(data_, size_, data_ptr + data_offset, size);
        data_offset += size;

        return ret;
      }
      else if constexpr (std::is_same_v<T, ccf::kv::EntryType>)
      {
        uint8_t entry_type = read_entry<uint8_t>();
        if (entry_type > static_cast<uint8_t>(ccf::kv::EntryType::MAX))
          throw std::logic_error(
            fmt::format("Invalid EntryType: {}", entry_type));

        return ccf::kv::EntryType(entry_type);
      }
      else if constexpr (std::is_same_v<T, std::string>)
      {
        size_t entry_offset = 0;
        read_size_prefixed_entry(entry_offset);

        return {data_ptr + entry_offset, data_ptr + data_offset};
      }
      else if constexpr (std::is_integral_v<T>)
      {
        return read_entry<T>();
      }
      else
      {
        static_assert(
          ccf::nonstd::dependent_false<T>::value,
          "Can't deserialise this type");
      }
    }

    bool is_eos()
    {
      return data_offset >= data_size;
    }
  };

}
