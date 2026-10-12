// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/siphash.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ranges.h>

namespace ccf
{
  namespace detail
  {
    template <typename I>
    concept ContiguousByteIterator =
      std::contiguous_iterator<I> && std::is_integral_v<std::iter_value_t<I>> &&
      sizeof(std::iter_value_t<I>) == 1 &&
      !std::is_same_v<std::iter_value_t<I>, bool> &&
      !std::is_volatile_v<std::remove_reference_t<std::iter_reference_t<I>>>;
  }

  class ByteVector
  {
    static constexpr size_t INLINE_CAPACITY = 16;
    static constexpr size_t HEAP_FLAG = 1;
    static constexpr size_t MAX_SIZE = std::min<size_t>(
      std::numeric_limits<ptrdiff_t>::max(),
      std::numeric_limits<size_t>::max() / 2);

    struct Inline
    {
      alignas(uint64_t) uint8_t bytes[INLINE_CAPACITY];

      // A user-provided constructor starts the array's lifetime without
      // zeroing unused capacity. Only initialized bytes are exposed by size().
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,modernize-use-equals-default)
      Inline() noexcept {}
    };

    struct Heap
    {
      uint8_t* data;
      size_t capacity;
    };

    union Storage
    {
      Inline small;
      Heap large;

      Storage() noexcept : small() {}
    } storage;
    size_t length_and_heap = 0;

    static_assert(std::is_trivially_copyable_v<Storage>);

    [[nodiscard]] bool allocated() const noexcept
    {
      return (length_and_heap & HEAP_FLAG) != 0;
    }

    void set_length(size_t count) noexcept
    {
      length_and_heap = (length_and_heap & HEAP_FLAG) | (count << 1);
    }

    void reset_inline() noexcept
    {
      std::construct_at(&storage.small);
      length_and_heap = 0;
    }

    [[nodiscard]] size_t extended_size(size_t additional) const
    {
      if (additional > MAX_SIZE - size())
      {
        throw std::length_error("ByteVector size overflow");
      }
      return size() + additional;
    }

    bool contains(const uint8_t* pointer) const noexcept
    {
      const auto less = std::less<const uint8_t*>{};
      return !less(pointer, data()) && less(pointer, data() + capacity());
    }

    uint8_t* initialize(size_t count)
    {
      if (count > MAX_SIZE)
      {
        throw std::length_error("ByteVector size overflow");
      }
      if (count > INLINE_CAPACITY)
      {
        // ByteVector owns this allocation until destruction or move.
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        auto* buffer = static_cast<uint8_t*>(std::malloc(count));
        if (buffer == nullptr)
        {
          throw std::bad_alloc();
        }
        storage.large = {buffer, count};
        length_and_heap = (count << 1) | HEAP_FLAG;
        return buffer;
      }
      length_and_heap = count << 1;
      return storage.small.bytes;
    }

    [[gnu::noinline]] void grow(size_t count)
    {
      if (count > MAX_SIZE)
      {
        throw std::length_error("ByteVector capacity overflow");
      }
      const auto previous_size = size();
      const auto previous_capacity = capacity();
      const auto next_capacity = std::max(
        count,
        previous_capacity <= MAX_SIZE / 2 ? previous_capacity * 2 : MAX_SIZE);
      uint8_t* replacement = nullptr;
      if (allocated())
      {
        // Keep ownership of the old buffer if realloc fails.
        // NOLINTBEGIN(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        replacement = static_cast<uint8_t*>(
          std::realloc(storage.large.data, next_capacity));
        // NOLINTEND(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        if (replacement == nullptr)
        {
          throw std::bad_alloc();
        }
      }
      else
      {
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        replacement = static_cast<uint8_t*>(std::malloc(next_capacity));
        if (replacement == nullptr)
        {
          throw std::bad_alloc();
        }
        std::memcpy(replacement, storage.small.bytes, previous_size);
      }
      storage.large = {replacement, next_capacity};
      length_and_heap = (previous_size << 1) | HEAP_FLAG;
    }

    void append_bytes(const uint8_t* source, size_t count)
    {
      if (count == 0)
      {
        return;
      }
      const auto previous_size = size();
      const auto next_size = extended_size(count);
      if (next_size > capacity() && contains(source))
      {
        const auto offset = static_cast<size_t>(source - data());
        if (offset > previous_size || count > previous_size - offset)
        {
          const ByteVector copy(source, source + count);
          append_bytes(copy.data(), copy.size());
          return;
        }
        grow(next_size);
        source = data() + offset;
      }
      else
      {
        reserve(next_size);
      }
      std::memmove(data() + previous_size, source, count);
      set_length(next_size);
    }

  public:
    using value_type = uint8_t;
    using size_type = size_t;
    using difference_type = ptrdiff_t;
    using pointer = uint8_t*;
    using const_pointer = const uint8_t*;
    using reference = uint8_t&;
    using const_reference = const uint8_t&;
    using iterator = pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    ByteVector() noexcept = default;

    explicit ByteVector(size_t count, uint8_t value = 0) : ByteVector()
    {
      std::memset(initialize(count), value, count);
    }

    template <std::input_iterator I>
    ByteVector(I first, I last) : ByteVector()
    {
      if (first == last)
      {
        return;
      }
      if constexpr (detail::ContiguousByteIterator<I>)
      {
        const auto count = static_cast<size_t>(last - first);
        std::memcpy(initialize(count), std::to_address(first), count);
      }
      else
      {
        append(first, last);
      }
    }

    ByteVector(std::initializer_list<uint8_t> values) :
      ByteVector(values.begin(), values.end())
    {}

    ByteVector(const ByteVector& other) : ByteVector()
    {
      if (other.empty())
      {
        return;
      }
      if (!other.allocated())
      {
        storage = other.storage;
        length_and_heap = other.length_and_heap;
      }
      else
      {
        const auto count = other.size();
        std::memcpy(initialize(count), other.storage.large.data, count);
      }
    }

    ByteVector(ByteVector&& other) noexcept :
      storage(other.storage),
      length_and_heap(other.length_and_heap)
    {
      other.reset_inline();
    }

    ByteVector& operator=(const ByteVector& other)
    {
      if (this != &other)
      {
        reserve(other.size());
        std::memcpy(data(), other.data(), other.size());
        set_length(other.size());
      }
      return *this;
    }

    ByteVector& operator=(ByteVector&& other) noexcept
    {
      if (this != &other)
      {
        if (allocated())
        {
          // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
          std::free(storage.large.data);
        }
        storage = other.storage;
        length_and_heap = other.length_and_heap;
        other.reset_inline();
      }
      return *this;
    }

    ByteVector& operator=(std::initializer_list<uint8_t> values)
    {
      assign(values);
      return *this;
    }

    ~ByteVector()
    {
      if (allocated())
      {
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        std::free(storage.large.data);
      }
    }

    pointer data() noexcept
    {
      return allocated() ? storage.large.data : storage.small.bytes;
    }

    [[nodiscard]] const_pointer data() const noexcept
    {
      return allocated() ? storage.large.data : storage.small.bytes;
    }

    [[nodiscard]] size_t size() const noexcept
    {
      return length_and_heap >> 1;
    }
    [[nodiscard]] size_t size_in_bytes() const noexcept
    {
      return size();
    }
    [[nodiscard]] bool empty() const noexcept
    {
      return size() == 0;
    }
    [[nodiscard]] constexpr size_t max_size() const noexcept
    {
      return MAX_SIZE;
    }
    [[nodiscard]] size_t capacity() const noexcept
    {
      return allocated() ? storage.large.capacity : INLINE_CAPACITY;
    }
    [[nodiscard]] size_t capacity_in_bytes() const noexcept
    {
      return capacity();
    }
    iterator begin() noexcept
    {
      return data();
    }
    [[nodiscard]] const_iterator begin() const noexcept
    {
      return data();
    }
    [[nodiscard]] const_iterator cbegin() const noexcept
    {
      return data();
    }
    iterator end() noexcept
    {
      return data() + size();
    }
    [[nodiscard]] const_iterator end() const noexcept
    {
      return data() + size();
    }
    [[nodiscard]] const_iterator cend() const noexcept
    {
      return end();
    }
    reverse_iterator rbegin() noexcept
    {
      return reverse_iterator(end());
    }
    [[nodiscard]] const_reverse_iterator rbegin() const noexcept
    {
      return const_reverse_iterator(end());
    }
    reverse_iterator rend() noexcept
    {
      return reverse_iterator(begin());
    }
    [[nodiscard]] const_reverse_iterator rend() const noexcept
    {
      return const_reverse_iterator(begin());
    }

    reference operator[](size_t index)
    {
      assert(index < size());
      return data()[index];
    }
    const_reference operator[](size_t index) const
    {
      assert(index < size());
      return data()[index];
    }
    reference front()
    {
      return (*this)[0];
    }
    [[nodiscard]] const_reference front() const
    {
      return (*this)[0];
    }
    reference back()
    {
      return (*this)[size() - 1];
    }
    [[nodiscard]] const_reference back() const
    {
      return (*this)[size() - 1];
    }

    void clear() noexcept
    {
      set_length(0);
    }
    void reserve(size_t count)
    {
      if (count > capacity())
      {
        grow(count);
      }
    }
    void resize(size_t count)
    {
      resize(count, 0);
    }
    void resize(size_t count, uint8_t value)
    {
      const auto previous_size = size();
      reserve(count);
      if (count > previous_size)
      {
        std::memset(data() + previous_size, value, count - previous_size);
      }
      set_length(count);
    }

    // Unlike resize, this exposes existing bytes without initializing them.
    void set_size(size_t count)
    {
      if (count > capacity())
      {
        throw std::length_error("ByteVector size exceeds reserved capacity");
      }
      set_length(count);
    }

    void push_back(uint8_t value)
    {
      const auto previous_size = size();
      if (previous_size == capacity())
      {
        grow(previous_size + 1);
      }
      data()[previous_size] = value;
      length_and_heap += 2;
    }
    template <typename... Args>
    void emplace_back(Args&&... args)
    {
      push_back(uint8_t(std::forward<Args>(args)...));
    }
    void pop_back()
    {
      assert(!empty());
      length_and_heap -= 2;
    }
    uint8_t pop_back_val()
    {
      const auto value = back();
      pop_back();
      return value;
    }

    template <std::input_iterator I>
    void append(I first, I last)
    {
      if (first == last)
      {
        return;
      }
      if constexpr (detail::ContiguousByteIterator<I>)
      {
        append_bytes(
          reinterpret_cast<const uint8_t*>(std::to_address(first)),
          static_cast<size_t>(last - first));
      }
      else
      {
        ByteVector copy;
        for (; first != last; ++first)
        {
          copy.push_back(static_cast<uint8_t>(*first));
        }
        append_bytes(copy.data(), copy.size());
      }
    }
    void append(size_t count, uint8_t value)
    {
      const auto previous_size = size();
      const auto next_size = extended_size(count);
      reserve(next_size);
      std::memset(data() + previous_size, value, count);
      set_length(next_size);
    }
    void append(std::initializer_list<uint8_t> values)
    {
      append(values.begin(), values.end());
    }
    void assign(size_t count, uint8_t value)
    {
      reserve(count);
      std::memset(data(), value, count);
      set_length(count);
    }
    void assign(std::initializer_list<uint8_t> values)
    {
      reserve(values.size());
      if (values.size() != 0)
      {
        std::memcpy(data(), values.begin(), values.size());
      }
      set_length(values.size());
    }

    iterator erase(const_iterator first, const_iterator last)
    {
      assert(first >= begin() && first <= last && last <= end());
      const auto offset = static_cast<size_t>(first - data());
      const auto count = static_cast<size_t>(last - first);
      auto* destination = data() + offset;
      std::memmove(destination, destination + count, size() - offset - count);
      set_length(size() - count);
      return destination;
    }
    iterator erase(const_iterator position)
    {
      assert(position != end());
      return erase(position, position + 1);
    }
    iterator insert(iterator position, uint8_t value)
    {
      return insert(position, size_t{1}, value);
    }
    iterator insert(iterator position, size_t count, uint8_t value)
    {
      assert(position >= begin() && position <= end());
      const auto offset = static_cast<size_t>(position - data());
      const auto previous_size = size();
      const auto next_size = extended_size(count);
      reserve(next_size);
      position = data() + offset;
      std::memmove(position + count, position, previous_size - offset);
      std::memset(position, value, count);
      set_length(next_size);
      return position;
    }
    template <std::input_iterator I>
    iterator insert(iterator position, I first, I last)
    {
      assert(position >= begin() && position <= end());
      if (first == last)
      {
        return position;
      }
      if constexpr (detail::ContiguousByteIterator<I>)
      {
        const auto* source =
          reinterpret_cast<const uint8_t*>(std::to_address(first));
        if (!contains(source))
        {
          const auto offset = static_cast<size_t>(position - data());
          const auto count = static_cast<size_t>(last - first);
          const auto previous_size = size();
          const auto next_size = extended_size(count);
          reserve(next_size);
          position = data() + offset;
          std::memmove(position + count, position, previous_size - offset);
          std::memcpy(position, source, count);
          set_length(next_size);
          return position;
        }
      }
      const ByteVector copy(first, last);
      return insert(position, copy.begin(), copy.end());
    }
    void insert(iterator position, std::initializer_list<uint8_t> values)
    {
      insert(position, values.begin(), values.end());
    }

    void swap(ByteVector& other) noexcept
    {
      std::swap(storage, other.storage);
      std::swap(length_and_heap, other.length_and_heap);
    }
    friend void swap(ByteVector& left, ByteVector& right) noexcept
    {
      left.swap(right);
    }
    bool operator==(const ByteVector& other) const noexcept
    {
      return size() == other.size() &&
        (empty() || std::memcmp(data(), other.data(), size()) == 0);
    }
    bool operator!=(const ByteVector& other) const noexcept
    {
      return !(*this == other);
    }
    bool operator<(const ByteVector& other) const noexcept
    {
      const auto common = std::min(size(), other.size());
      const auto comparison =
        common == 0 ? 0 : std::memcmp(data(), other.data(), common);
      return comparison < 0 || (comparison == 0 && size() < other.size());
    }
  };
}

namespace std
{
  template <>
  struct hash<ccf::ByteVector>
  {
    size_t operator()(const ccf::ByteVector& v) const
    {
      static constexpr ccf::siphash::SipKey k{
        0x7720796f726c694b, 0x2165726568207361};
      return ccf::siphash::siphash<2, 4>(v.data(), v.size(), k);
    }
  };
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::ByteVector>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::ByteVector& e, FormatContext& ctx) const
  {
    // This is the same as std::isprint, but independent of the current locale.
    constexpr auto first_printable = 0x20;
    constexpr auto last_printable = 0x7e;
    auto printable = [](uint8_t b) {
      return b >= first_printable && b <= last_printable;
    };
    if (std::all_of(e.begin(), e.end(), printable))
    {
      return format_to(
        ctx.out(),
        "<uint8[{}]: ascii={}>",
        e.size(),
        std::string(e.begin(), e.end()));
    }
    return format_to(
      ctx.out(), "<uint8[{}]: hex={:02x}>", e.size(), fmt::join(e, " "));
  }
};
FMT_END_NAMESPACE
