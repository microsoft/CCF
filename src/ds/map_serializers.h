// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "ds/serialized.h"

#include <span>

namespace map
{
  template <class T>
  inline size_t get_size(const T& data)
  {
    return sizeof(uint64_t) + sizeof(data);
  }

  static uint32_t get_padding(uint32_t size)
  {
    uint32_t padding = size % sizeof(uintptr_t);
    if (padding != 0)
    {
      padding = sizeof(uintptr_t) - padding;
    }
    return padding;
  }

  static uint32_t add_padding(uint32_t data_size, uint8_t*& data, size_t& size)
  {
    constexpr uintptr_t padding = 0;
    uint32_t padding_size = get_padding(data_size);
    if (padding_size != 0)
    {
      serialized::write(
        data, size, reinterpret_cast<const uint8_t*>(&padding), padding_size);
    }
    return padding_size;
  }

  template <class T>
  static size_t get_serialized_size_with_padding(const T& t)
  {
    const uint32_t t_size = get_size(t);
    return t_size + get_padding(t_size);
  }

  template <class T>
  inline size_t serialize(const T& t, uint8_t*& data, size_t& size)
  {
    uint64_t data_size = sizeof(T);
    serialized::write(
      data,
      size,
      reinterpret_cast<const uint8_t*>(&data_size),
      sizeof(uint64_t));
    serialized::write(
      data, size, reinterpret_cast<const uint8_t*>(&t), sizeof(T));
    return sizeof(uint64_t) + sizeof(T);
  }

  template <class T>
  inline T deserialize(const uint8_t*& data, size_t& size)
  {
    size_t result = serialized::read<size_t>(data, size);
    (void)result;
    CCF_ASSERT_FMT(
      result == sizeof(T), "result:{} == sizeof(T):{}", result, sizeof(T));
    return serialized::read<T>(data, size);
  }

  template <class M>
  static M deserialize_map(std::span<const uint8_t> serialized_state)
  {
    using KeyType = typename M::KeyType;
    using ValueType = typename M::ValueType;

    M map;
    const uint8_t* data = serialized_state.data();
    size_t size = serialized_state.size();

    while (size != 0)
    {
      // Deserialize the key
      size_t key_size = size;
      KeyType key = deserialize<KeyType>(data, size);
      key_size -= size;
      serialized::skip(data, size, get_padding(key_size));

      // Deserialize the value
      size_t value_size = size;
      ValueType value = deserialize<ValueType>(data, size);
      value_size -= size;
      serialized::skip(data, size, get_padding(value_size));
      map = map.put(key, value);
    }
    return map;
  }
}