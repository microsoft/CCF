// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "msgpack/encode.h"

#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ccf::msgpack
{
  inline uint32_t container_size(size_t size)
  {
    if (size > std::numeric_limits<uint32_t>::max())
    {
      throw std::length_error("Container exceeds MessagePack size limit");
    }
    return static_cast<uint32_t>(size);
  }

  inline void write_key(std::vector<uint8_t>& out, std::string_view key)
  {
    write_str(out, key);
  }

  template <typename Enum>
    requires std::is_enum_v<Enum>
  inline void write_msgpack(std::vector<uint8_t>& out, Enum value)
  {
    // Reuse DECLARE_JSON_ENUM's mapping without constructing a JSON value.
    std::string_view name;
    to_json(name, value);
    write_str(out, name);
  }

  template <typename Integer>
    requires std::is_integral_v<Integer>
  inline void write_msgpack(std::vector<uint8_t>& out, Integer value)
  {
    if constexpr (std::is_same_v<Integer, bool>)
      write_bool(out, value);
    else if constexpr (std::is_signed_v<Integer>)
      write_int(out, value);
    else
      write_uint(out, value);
  }

  template <typename T>
  struct Field
  {
    std::string_view name;
    const T& value;
  };

  inline void write_msgpack(std::vector<uint8_t>& out, std::string_view value)
  {
    write_str(out, value);
  }

  template <typename Write>
    requires std::is_invocable_v<Write, std::vector<uint8_t>&>
  inline void write_msgpack(std::vector<uint8_t>& out, const Write& write)
  {
    write(out);
  }

  template <typename... Fields>
  inline void write_fields(std::vector<uint8_t>& out, const Fields&... fields)
  {
    write_map_header(out, sizeof...(Fields));
    ((write_key(out, fields.name), write_msgpack(out, fields.value)), ...);
  }

  template <typename T, typename WriteValue>
  inline void write_optional(
    std::vector<uint8_t>& out,
    std::string_view key,
    const std::optional<T>& value,
    WriteValue&& write_value)
  {
    if (value.has_value())
    {
      write_key(out, key);
      write_value(out, *value);
    }
  }
}
