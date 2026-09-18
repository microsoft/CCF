// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "msgpack/fields.h"

namespace ccf::msgpack
{
  template <typename T>
  constexpr uint32_t msgpack_optional_fields_count(const T& /*value*/)
  {
    return 0;
  }

  template <typename T>
  inline void write_msgpack_optional_fields(
    std::vector<uint8_t>& /*out*/, const T& /*value*/)
  {}
}

// Declare these in the type's namespace so nested fields use ADL.
// This reuses JSON's field-list machinery, not its object serialization.
// Required fields are emitted in declaration order, including inherited
// members. Optional fields follow required fields, in declaration order, and
// absent std::optional values are omitted rather than encoded as nil.
#define DECLARE_MSGPACK_TYPE(TYPE) \
  inline void write_msgpack(std::vector<uint8_t>& out, const TYPE& value)

#define DECLARE_MSGPACK_TYPE_WITH_OPTIONAL_FIELDS(TYPE) \
  inline uint32_t msgpack_optional_fields_count(const TYPE& value); \
  inline void write_msgpack_optional_fields( \
    std::vector<uint8_t>& out, const TYPE& value); \
  inline void write_msgpack(std::vector<uint8_t>& out, const TYPE& value)

#define CCF_MSGPACK_FIELD_FOR_JSON_NEXT(TYPE, MEMBER) \
  ccf::msgpack::write_pair(out, #MEMBER, value.MEMBER);
#define CCF_MSGPACK_FIELD_FOR_JSON_FINAL(TYPE, MEMBER) \
  CCF_MSGPACK_FIELD_FOR_JSON_NEXT(TYPE, MEMBER)

#define CCF_MSGPACK_COUNT_FOR_JSON_NEXT(TYPE, MEMBER) +1
#define CCF_MSGPACK_COUNT_FOR_JSON_FINAL(TYPE, MEMBER) +1

#define DECLARE_MSGPACK_FIELDS(TYPE, ...) \
  inline void write_msgpack( \
    std::vector<uint8_t>& out, [[maybe_unused]] const TYPE& value) \
  { \
    using ccf::msgpack::msgpack_optional_fields_count; \
    using ccf::msgpack::write_msgpack_optional_fields; \
    ccf::msgpack::write_map_header( \
      out, \
      msgpack_optional_fields_count(value) __VA_OPT__(_FOR_JSON_COUNT_NN( \
        __VA_ARGS__)(POP1)(CCF_MSGPACK_COUNT, TYPE, __VA_ARGS__))); \
    __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      CCF_MSGPACK_FIELD, TYPE, __VA_ARGS__)) \
    write_msgpack_optional_fields(out, value); \
  } \
  REQUIRES_SEMICOLON_TERMINATION

#define CCF_MSGPACK_OPTIONAL_COUNT_FOR_JSON_NEXT(TYPE, MEMBER) \
  +static_cast<uint32_t>(value.MEMBER.has_value())
#define CCF_MSGPACK_OPTIONAL_COUNT_FOR_JSON_FINAL(TYPE, MEMBER) \
  CCF_MSGPACK_OPTIONAL_COUNT_FOR_JSON_NEXT(TYPE, MEMBER)
#define CCF_MSGPACK_OPTIONAL_WRITE_FOR_JSON_NEXT(TYPE, MEMBER) \
  ccf::msgpack::write_optional(out, #MEMBER, value.MEMBER);
#define CCF_MSGPACK_OPTIONAL_WRITE_FOR_JSON_FINAL(TYPE, MEMBER) \
  CCF_MSGPACK_OPTIONAL_WRITE_FOR_JSON_NEXT(TYPE, MEMBER)

#define DECLARE_MSGPACK_OPTIONAL_FIELDS(TYPE, ...) \
  inline uint32_t msgpack_optional_fields_count( \
    [[maybe_unused]] const TYPE& value) \
  { \
    return 0 __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      CCF_MSGPACK_OPTIONAL_COUNT, TYPE, __VA_ARGS__)); \
  } \
  inline void write_msgpack_optional_fields( \
    [[maybe_unused]] std::vector<uint8_t>& out, \
    [[maybe_unused]] const TYPE& value){ \
    __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      CCF_MSGPACK_OPTIONAL_WRITE, \
      TYPE, \
      __VA_ARGS__))} REQUIRES_SEMICOLON_TERMINATION
