// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"
#include "generic_serialise_wrapper.h"

#include <array>
#include <cstring>
#include <limits>
#include <small_vector/SmallVector.h>
#include <span>
#include <tuple>
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

      auto* data_ = buf.data() + size_before;
      auto size_ = buf.size() - size_before;
      serialized::write(data_, size_, t);
    }

    template <typename T>
    void serialise_vector(const T& entry)
    {
      size_t entry_size_bytes = sizeof(typename T::value_type) * entry.size();
      size_t size_before = buf.size();

      buf.resize(buf.size() + entry_size_bytes);

      auto* data_ = buf.data() + size_before;
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

      auto* data_ = buf.data() + size_before;
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

      auto* data_ = buf.data() + size_before;
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
  private:
    void require_bytes(size_t required, const char* description) const
    {
      if (required > span_.size())
      {
        throw std::runtime_error(fmt::format(
          "Expected {} bytes for {}, found only {}",
          required,
          description,
          span_.size()));
      }
    }

    /** Reads the next size-prefixed payload, returning a span over it.
     */
    std::span<const uint8_t> read_size_prefixed_entry()
    {
      const auto entry_size = read_entry<size_t>();
      require_bytes(entry_size, "size-prefixed entry");
      const auto content = span_.subspan(0, entry_size);
      span_ = span_.subspan(entry_size);
      return content;
    }

    std::span<const uint8_t> span_{};

  public:
    /** Reads the next entry of a trivially-copyable type, advancing the cursor.
     */
    template <typename T>
      requires std::is_trivially_copyable_v<T>
    T read_entry()
    {
      require_bytes(sizeof(T), "fixed-size entry");
      T entry;
      std::memcpy(&entry, span_.data(), sizeof(T));
      span_ = span_.subspan(sizeof(T));
      return entry;
    }

    RawReader(const RawReader& other) = delete;
    RawReader& operator=(const RawReader& other) = delete;

    RawReader(std::span<const uint8_t> data = {})
    {
      init(data);
    }

    void init(std::span<const uint8_t> data)
    {
      span_ = data;
    }

    template <typename T>
    T read_next()
    {
      if constexpr (
        ccf::nonstd::is_std_vector<T>::value ||
        std::is_same_v<T, ccf::kv::serialisers::SerialisedEntry>)
      {
        const auto entry_span = read_size_prefixed_entry();
        using Element = typename T::value_type;
        const auto entry_size = entry_span.size();
        if (entry_size % sizeof(Element) != 0)
        {
          throw std::runtime_error(fmt::format(
            "Size-prefixed entry of {} bytes is not divisible by element size "
            "{}",
            entry_size,
            sizeof(Element)));
        }

        T ret;
        const auto element_count = entry_size / sizeof(Element);
        if (element_count > ret.max_size())
        {
          throw std::length_error(fmt::format(
            "Size-prefixed entry contains too many elements ({})",
            element_count));
        }
        ret.resize(element_count);
        if (entry_size > 0)
        {
          std::memcpy(ret.data(), entry_span.data(), entry_size);
        }
        return ret;
      }
      else if constexpr (ccf::nonstd::is_std_array<T>::value)
      {
        T ret{};
        auto* data_ = reinterpret_cast<uint8_t*>(ret.data());
        constexpr auto element_count = std::tuple_size_v<T>;
        static_assert(
          element_count <=
          std::numeric_limits<size_t>::max() / sizeof(typename T::value_type));
        constexpr size_t size = element_count * sizeof(typename T::value_type);
        require_bytes(size, "fixed-size array");
        if constexpr (size > 0)
        {
          std::memcpy(data_, span_.data(), size);
          span_ = span_.subspan(size);
        }
        return ret;
      }
      else if constexpr (std::is_same_v<T, ccf::kv::EntryType>)
      {
        auto entry_type = read_entry<uint8_t>();
        if (entry_type > static_cast<uint8_t>(ccf::kv::EntryType::MAX))
        {
          throw std::logic_error(
            fmt::format("Invalid EntryType: {}", entry_type));
        }

        return ccf::kv::EntryType(entry_type);
      }
      else if constexpr (std::is_same_v<T, std::string>)
      {
        const auto entry_span = read_size_prefixed_entry();
        return {entry_span.begin(), entry_span.end()};
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

    [[nodiscard]] bool is_eos() const
    {
      return span_.empty();
    }
  };

}
