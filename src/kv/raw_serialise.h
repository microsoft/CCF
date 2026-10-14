// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"
#include "generic_serialise_wrapper.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ccf::kv
{
  class RawWriter
  {
  private:
    static constexpr size_t INLINE_CAPACITY = 256;
    static constexpr size_t MAX_SIZE = std::numeric_limits<ptrdiff_t>::max();

    std::array<uint8_t, INLINE_CAPACITY> local;
    uint8_t* data = local.data();
    size_t used = 0;
    size_t capacity = INLINE_CAPACITY;

    [[gnu::noinline]] void grow(size_t required)
    {
      if (required > MAX_SIZE)
      {
        throw std::length_error("RawWriter capacity overflow");
      }
      const auto doubled = capacity <= MAX_SIZE / 2 ? capacity * 2 : MAX_SIZE;
      const auto requested = std::max(required, doubled);
      // Leave room for small fields following a large payload.
      const auto next =
        requested <= MAX_SIZE - 63 ? (requested + 63) & ~size_t{63} : MAX_SIZE;
      uint8_t* replacement = nullptr;
      if (data == local.data())
      {
        // RawWriter owns this allocation until destruction or move.
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        replacement = static_cast<uint8_t*>(std::malloc(next));
        if (replacement == nullptr)
        {
          throw std::bad_alloc();
        }
        std::memcpy(replacement, data, used);
      }
      else
      {
        // Keep ownership of the old buffer if realloc fails.
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        replacement = static_cast<uint8_t*>(std::realloc(data, next));
        if (replacement == nullptr)
        {
          throw std::bad_alloc();
        }
      }
      data = replacement;
      capacity = next;
    }

    uint8_t* extend(size_t additional)
    {
      if (additional > MAX_SIZE - used)
      {
        throw std::length_error("RawWriter size overflow");
      }
      const auto previous = used;
      const auto required = previous + additional;
      if (required > capacity)
      {
        grow(required);
      }
      used = required;
      return data + previous;
    }

    static size_t size_with_prefix(size_t count, size_t element_size = 1)
    {
      if (count > (MAX_SIZE - sizeof(size_t)) / element_size)
      {
        throw std::length_error("RawWriter payload size overflow");
      }
      return sizeof(size_t) + count * element_size;
    }

    void append_size_prefixed(const uint8_t* source, size_t total_size)
    {
      auto* destination = extend(total_size);
      const auto payload_size = total_size - sizeof(size_t);
      std::memcpy(destination, &payload_size, sizeof(payload_size));
      if (payload_size != 0)
      {
        std::memcpy(destination + sizeof(size_t), source, payload_size);
      }
    }

    void move_from(RawWriter& other) noexcept
    {
      if (other.data == other.local.data())
      {
        std::memcpy(data, other.data, other.used);
      }
      else
      {
        data = std::exchange(other.data, other.local.data());
        capacity = std::exchange(other.capacity, INLINE_CAPACITY);
      }
      used = std::exchange(other.used, 0);
    }

  public:
    // Appends initialize every exported byte; unused inline capacity need not
    // be zeroed by construction.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,modernize-use-equals-default)
    RawWriter() noexcept {}
    RawWriter(const RawWriter& other) : RawWriter()
    {
      if (other.used > capacity)
      {
        grow(other.used);
      }
      std::memcpy(data, other.data, other.used);
      used = other.used;
    }
    RawWriter(RawWriter&& other) noexcept : RawWriter()
    {
      move_from(other);
    }
    RawWriter& operator=(const RawWriter& other)
    {
      if (this != &other)
      {
        if (other.used > capacity)
        {
          grow(other.used);
        }
        std::memcpy(data, other.data, other.used);
        used = other.used;
      }
      return *this;
    }
    RawWriter& operator=(RawWriter&& other) noexcept
    {
      if (this != &other)
      {
        if (data != local.data())
        {
          // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
          std::free(data);
        }
        data = local.data();
        capacity = INLINE_CAPACITY;
        move_from(other);
      }
      return *this;
    }
    ~RawWriter()
    {
      if (data != local.data())
      {
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        std::free(data);
      }
    }

    template <typename T>
    static size_t serialised_size(const T& entry)
    {
      if constexpr (
        ccf::nonstd::is_std_vector<T>::value ||
        std::is_same_v<T, ccf::kv::serialisers::SerialisedEntry>)
      {
        return size_with_prefix(entry.size(), sizeof(typename T::value_type));
      }
      else if constexpr (std::is_same_v<T, ccf::crypto::Sha256Hash>)
      {
        return sizeof(entry.h);
      }
      else if constexpr (std::is_same_v<T, EntryType>)
      {
        return sizeof(uint8_t);
      }
      else if constexpr (std::is_same_v<T, std::string>)
      {
        return size_with_prefix(entry.size());
      }
      else if constexpr (std::is_integral_v<T>)
      {
        return sizeof(T);
      }
      else
      {
        static_assert(
          ccf::nonstd::dependent_false<T>::value, "Can't serialise this type");
      }
    }

    template <typename T>
    void append(const T& entry)
    {
      if constexpr (
        ccf::nonstd::is_std_vector<T>::value ||
        std::is_same_v<T, ccf::kv::serialisers::SerialisedEntry>)
      {
        append_size_prefixed(
          reinterpret_cast<const uint8_t*>(entry.data()),
          serialised_size(entry));
      }
      else if constexpr (std::is_same_v<T, ccf::crypto::Sha256Hash>)
      {
        std::memcpy(extend(entry.h.size()), entry.h.data(), entry.h.size());
      }
      else if constexpr (std::is_same_v<T, EntryType>)
      {
        append(static_cast<uint8_t>(entry));
      }
      else if constexpr (std::is_same_v<T, std::string>)
      {
        append_size_prefixed(
          reinterpret_cast<const uint8_t*>(entry.data()),
          serialised_size(entry));
      }
      else if constexpr (std::is_integral_v<T>)
      {
        std::memcpy(extend(sizeof(T)), &entry, sizeof(T));
      }
      else
      {
        static_assert(
          ccf::nonstd::dependent_false<T>::value, "Can't serialise this type");
      }
    }

    void clear()
    {
      used = 0;
    }

    [[nodiscard]] size_t size() const
    {
      return used;
    }

    std::vector<uint8_t> get_raw_data()
    {
      return {data, data + used};
    }
  };

  class SizeWriter
  {
  private:
    size_t total_size = 0;

  public:
    SizeWriter() = default;

    template <typename T>
    void append(const T& entry)
    {
      const auto additional = RawWriter::serialised_size(entry);
      if (
        additional > size_t(std::numeric_limits<ptrdiff_t>::max()) - total_size)
      {
        throw std::length_error("SizeWriter size overflow");
      }
      total_size += additional;
    }

    void clear()
    {
      total_size = 0;
    }

    [[nodiscard]] size_t size() const
    {
      return total_size;
    }

    std::vector<uint8_t> get_raw_data()
    {
      throw std::logic_error("SizeWriter does not retain serialised data");
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

    std::span<const uint8_t> span_;

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
