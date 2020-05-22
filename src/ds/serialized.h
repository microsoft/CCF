// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace serialized
{
  template <class T>
  T peek(const uint8_t*& data, size_t& size)
  {
    if (size < sizeof(T))
      throw std::logic_error(
        "Insufficient space (peek<T>: " + std::to_string(size) + " < " +
        std::to_string(sizeof(T)) + ")");

    return *(T*)data;
  }

  template <class T>
  __attribute__((no_sanitize("undefined"))) T read(
    const uint8_t*& data, size_t& size)
  {
    if (size < sizeof(T))
      throw std::logic_error(
        "Insufficient space (read<T>: " + std::to_string(size) + " < " +
        std::to_string(sizeof(T)) + ")");

    T v = *(T*)data;
    data += sizeof(T);
    size -= sizeof(T);
    return v;
  }

  template <>
  inline std::string read(const uint8_t*& data, size_t& size)
  {
    size_t len = read<size_t>(data, size);
    std::string v(data, data + len);
    data += len;
    size -= len;
    return v;
  }

  inline std::vector<uint8_t> read(
    const uint8_t*& data, size_t& size, size_t block_size)
  {
    if (size < block_size)
      throw std::logic_error(
        "Insufficient space (read block: " + std::to_string(size) + " < " +
        std::to_string(block_size) + ")");

    std::vector<uint8_t> v(data, data + block_size);
    data += block_size;
    size -= block_size;
    return v;
  }

  // Read a length-prefixed (uint16_t) buffer into a string view
  inline std::string_view read_lpsv(const uint8_t*& data, size_t& size)
  {
    auto len = read<uint16_t>(data, size);
    if (size < len)
      throw std::logic_error(
        "Insufficient space (read block: " + std::to_string(size) + " < " +
        std::to_string(len) + ")");
    std::string_view v((char*)data, len);
    data += len;
    size -= len;
    return v;
  };

  template <class T>
  __attribute__((no_sanitize("undefined"))) void write(
    uint8_t*& data, size_t& size, T v)
  {
    if (size < sizeof(T))
      throw std::logic_error(
        "Insufficient space (write<T>: " + std::to_string(size) + " < " +
        std::to_string(sizeof(T)) + ")");

    *reinterpret_cast<T*>(data) = v;
    data += sizeof(T);
    size -= sizeof(T);
  }

  inline void write(
    uint8_t*& data, size_t& size, const uint8_t* block, size_t block_size)
  {
    if (size < block_size)
      throw std::logic_error(
        "Insufficient space (write block: " + std::to_string(size) + " < " +
        std::to_string(block_size) + ")");

    if (block_size > 0)
    {
      std::memcpy(data, block, block_size);
    }

    data += block_size;
    size -= block_size;
  }

  inline void write(uint8_t*& data, size_t& size, const std::string& v)
  {
    if (size < (sizeof(size_t) + v.size()))
      throw std::logic_error(
        "Insufficient space (write string: " + std::to_string(size) + " < " +
        std::to_string(sizeof(size_t) + v.size()) + ")");

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
      throw std::logic_error(
        "Insufficient space (overlay<T>: " + std::to_string(size) + " < " +
        std::to_string(sizeof(T)) + ")");

    T* v = (T*)data;
    data += sizeof(T);
    size -= sizeof(T);
    return *v;
  }

  inline void skip(const uint8_t*& data, size_t& size, size_t skip)
  {
    if (size < skip)
      throw std::logic_error(
        "Insufficient space (skip: " + std::to_string(size) + " < " +
        std::to_string(skip) + ")");

    data += skip;
    size -= skip;
  }
}
