// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "msgpack/encode.h"

#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
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
    {
      write_bool(out, value);
    }
    else if constexpr (std::is_signed_v<Integer>)
    {
      write_int(out, value);
    }
    else
    {
      write_uint(out, value);
    }
  }

  inline void write_msgpack(std::vector<uint8_t>& out, std::string_view value)
  {
    write_str(out, value);
  }

  template <typename... Args>
  inline constexpr bool map_arguments = false;

  template <>
  inline constexpr bool map_arguments<> = true;

  template <typename Key, typename Value, typename... Rest>
  inline constexpr bool map_arguments<Key, Value, Rest...> =
    std::is_convertible_v<const Key&, std::string_view> &&
    map_arguments<Rest...>;

  template <typename Key, typename Value>
    requires std::is_convertible_v<const Key&, std::string_view>
  inline void write_pair(
    std::vector<uint8_t>& out, const Key& key, const Value& value)
  {
    write_key(out, key);
    write_msgpack(out, value);
  }

  template <typename... Args>
    requires map_arguments<Args...>
  inline void write_map(std::vector<uint8_t>& out, const Args&... args)
  {
    write_map_header(out, sizeof...(Args) / 2);
    const auto refs = std::tie(args...);
    [&]<size_t... I>(std::index_sequence<I...>) {
      (write_pair(out, std::get<2 * I>(refs), std::get<2 * I + 1>(refs)), ...);
    }(std::make_index_sequence<sizeof...(Args) / 2>{});
  }

  // Borrowed nested maps must be consumed within the creating full expression.
  template <typename... Args>
  struct MapView
  {
    std::tuple<const Args&...> args;
  };

  template <typename... Args>
    requires map_arguments<Args...>
  inline auto map(const Args&... args)
  {
    return MapView<Args...>{{args...}};
  }

  template <typename... Args>
  inline void write_msgpack(
    std::vector<uint8_t>& out, const MapView<Args...>& value)
  {
    std::apply(
      [&](const auto&... args) { write_map(out, args...); }, value.args);
  }

  template <typename T>
  inline void write_optional(
    std::vector<uint8_t>& out,
    std::string_view key,
    const std::optional<T>& value)
  {
    if (value.has_value())
    {
      write_pair(out, key, *value);
    }
  }
}
