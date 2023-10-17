// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace serialized
{
  class InsufficientSpaceException : public std::exception
  {
  private:
    std::string msg;

  public:
    InsufficientSpaceException(const std::string& msg_) : msg(msg_) {}

    const char* what() const throw() override
    {
      return msg.c_str();
    }
  };

  template <class T>
  T peek(const uint8_t*& data, size_t& size)
  {
    if (size < sizeof(T))
    {
      throw InsufficientSpaceException(
        fmt::format("Insufficient space (peek<T>: {} < {})", size, sizeof(T)));
    }

    return *(T*)data;
  }

  template <class T>
  T read(const uint8_t*& data, size_t& size)
  {
    if (size < sizeof(T))
    {
      throw InsufficientSpaceException(
        fmt::format("Insufficient space (read<T>: {} < {})", size, sizeof(T)));
    }

    T v;
    std::memcpy(reinterpret_cast<uint8_t*>(&v), data, sizeof(T));
    data += sizeof(T);
    size -= sizeof(T);
    return v;
  }

  template <>
  inline std::string read(const uint8_t*& data, size_t& size)
  {
    size_t len = read<size_t>(data, size);
    if (size < len)
    {
      throw InsufficientSpaceException(
        fmt::format("Insufficient space (read string: {} < {})", size, len));
    }

    std::string v(data, data + len);
    data += len;
    size -= len;
    return v;
  }

  inline std::vector<uint8_t> read(
    const uint8_t*& data, size_t& size, size_t block_size)
  {
    if (size < block_size)
    {
      throw InsufficientSpaceException(fmt::format(
        "Insufficient space (read block: {} < {})", size, block_size));
    }

    std::vector<uint8_t> v(data, data + block_size);
    data += block_size;
    size -= block_size;
    return v;
  }

  template <class T>
  void write(uint8_t*& data, size_t& size, const T& v)
  {
    if (size < sizeof(T))
    {
      throw InsufficientSpaceException(
        fmt::format("Insufficient space (write<T>: {} < {})", size, sizeof(T)));
    }

    const auto src = reinterpret_cast<const uint8_t*>(&v);
    std::memcpy(data, src, sizeof(T));
    data += sizeof(T);
    size -= sizeof(T);
  }

  inline void write(
    uint8_t*& data, size_t& size, const uint8_t* block, size_t block_size)
  {
    if (size < block_size)
    {
      throw InsufficientSpaceException(fmt::format(
        "Insufficient space (write block: {} < {})", size, block_size));
    }

    if (block_size > 0)
    {
      std::memcpy(data, block, block_size);
    }

    data += block_size;
    size -= block_size;
  }

  inline void write(uint8_t*& data, size_t& size, const std::string& v)
  {
    const auto string_size = sizeof(size_t) + v.size();
    if (size < string_size)
    {
      throw InsufficientSpaceException(fmt::format(
        "Insufficient space (write string: {} < {})", size, string_size));
    }

    write(data, size, v.size());
    write(data, size, (const uint8_t*)v.data(), v.size());
  }

  inline void write_lps(uint8_t*& data, size_t& size, const std::string& v)
  {
    write<uint16_t>(data, size, v.size());
    write(data, size, (const uint8_t*)v.data(), v.size());
  }

  template <class T>
  T& overlay(const uint8_t*& data, size_t& size)
  {
    if (size < sizeof(T))
    {
      throw InsufficientSpaceException(fmt::format(
        "Insufficient space (overlay<T>: {} < {})", size, sizeof(T)));
    }

    T* v = (T*)data;
    data += sizeof(T);
    size -= sizeof(T);
    return *v;
  }

  inline void skip(const uint8_t*& data, size_t& size, size_t skip)
  {
    if (size < skip)
    {
      throw InsufficientSpaceException(
        fmt::format("Insufficient space (skip: {} < {})", size, skip));
    }

    data += skip;
    size -= skip;
  }
}
