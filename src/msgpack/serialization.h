// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "msgpack/encode.h"

#include <limits>
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

  template <typename Enum>
    requires std::is_enum_v<Enum>
  inline void write_msgpack(std::vector<uint8_t>& out, Enum value)
  {
    // Reuse DECLARE_JSON_ENUM's mapping without constructing a JSON value.
    std::string_view name;
    to_json(name, value);
    write_str(out, name);
  }

  // is_integral_v<Bool> but also is_integral_v<u32> so we need to
  // group them here and check if bool first
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
}

// Declare these in the type's namespace so nested fields use ADL.
// This reuses JSON's field-list machinery, not its object serialization.
// Required fields are emitted in declaration order, including inherited
// members.
#define DECLARE_MSGPACK_TYPE(TYPE) \
  inline void write_msgpack(std::vector<uint8_t>& out, const TYPE& value)

#define CCF_MSGPACK_FIELD_FOR_JSON_NEXT(TYPE, MEMBER) \
  ccf::msgpack::write_str(out, #MEMBER); \
  write_msgpack(out, value.MEMBER);
#define CCF_MSGPACK_FIELD_FOR_JSON_FINAL(TYPE, MEMBER) \
  CCF_MSGPACK_FIELD_FOR_JSON_NEXT(TYPE, MEMBER)

#define CCF_MSGPACK_COUNT_FOR_JSON_NEXT(TYPE, MEMBER) +1
#define CCF_MSGPACK_COUNT_FOR_JSON_FINAL(TYPE, MEMBER) +1

#define DECLARE_MSGPACK_FIELDS(TYPE, ...) \
  inline void write_msgpack( \
    std::vector<uint8_t>& out, [[maybe_unused]] const TYPE& value) \
  { \
    using ccf::msgpack::write_msgpack; \
    ccf::msgpack::write_map_header( \
      out, \
      0 __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
        CCF_MSGPACK_COUNT, TYPE, __VA_ARGS__))); \
    __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      CCF_MSGPACK_FIELD, TYPE, __VA_ARGS__)) \
  } \
  REQUIRES_SEMICOLON_TERMINATION
