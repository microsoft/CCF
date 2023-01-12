// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/crypto/base64.h"
#include "ccf/ds/json_schema.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <sstream>

/** Represents a field within a JSON object. Tuples of these can be used in
 * schema generation.
 */
template <typename T>
struct JsonField
{
  using Target = T;
  char const* name;
};

class JsonParseError : public std::invalid_argument
{
public:
  std::vector<std::string> pointer_elements = {};

  using std::invalid_argument::invalid_argument;

  std::string pointer() const
  {
    return fmt::format(
      "#/{}",
      fmt::join(pointer_elements.crbegin(), pointer_elements.crend(), "/"));
  }

  std::string describe() const
  {
    return fmt::format("At {}: {}", pointer(), what());
  }
};

namespace std
{
  template <typename T>
  inline void to_json(nlohmann::json& j, const std::optional<T>& t)
  {
    if (t.has_value())
    {
      j = t.value();
    }
  }

  template <typename T>
  inline void from_json(const nlohmann::json& j, std::optional<T>& t)
  {
    if (!j.is_null())
    {
      t = j.get<T>();
    }
  }

  template <typename T>
  inline void to_json(nlohmann::json& j, const std::vector<T>& t)
  {
    if constexpr (std::is_same_v<T, uint8_t>)
    {
      j = crypto::b64_from_raw(t);
    }
    else
    {
      j = nlohmann::json::array();
      for (const auto& e : t)
      {
        j.push_back(e);
      }
    }
  }

  template <typename T>
  inline void from_json(const nlohmann::json& j, std::vector<T>& t)
  {
    if constexpr (std::is_same_v<T, uint8_t>)
    {
      if (j.is_string())
      {
        try
        {
          t = crypto::raw_from_b64(j.get<std::string>());
          return;
        }
        catch (const std::exception& e)
        {
          throw JsonParseError(fmt::format(
            "Vector of bytes object \"{}\" is not valid base64", j.dump()));
        }
      }
    }

    // Fall-through. So we can convert _from_ [1,2,3] to
    // std::vector<uint8_t>, but would prefer (and will produce in to_json) a
    // base64 string

    if (!j.is_array())
    {
      throw JsonParseError(
        fmt::format("Vector object \"{}\" is not an array", j.dump()));
    }

    for (auto i = 0u; i < j.size(); ++i)
    {
      try
      {
        t.push_back(j.at(i).template get<T>());
      }
      catch (JsonParseError& jpe)
      {
        jpe.pointer_elements.push_back(std::to_string(i));
        throw;
      }
    }
  }
}

// FOREACH macro machinery for counting args

// -Wpedantic flags token pasting of __VA_ARGS__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

#define __FOR_JSON_COUNT_NN( \
  _0, \
  _1, \
  _2, \
  _3, \
  _4, \
  _5, \
  _6, \
  _7, \
  _8, \
  _9, \
  _10, \
  _11, \
  _12, \
  _13, \
  _14, \
  _15, \
  _16, \
  _17, \
  _18, \
  _19, \
  _20, \
  _21, \
  _22, \
  _23, \
  _24, \
  _25, \
  _26, \
  _27, \
  _28, \
  _29, \
  _30, \
  N, \
  ...) \
  _FOR_JSON_##N
#define _FOR_JSON_COUNT_NN_WITH_0(...) \
  __FOR_JSON_COUNT_NN( \
    __VA_ARGS__, \
    30, \
    29, \
    28, \
    27, \
    26, \
    25, \
    24, \
    23, \
    22, \
    21, \
    20, \
    19, \
    18, \
    17, \
    16, \
    15, \
    14, \
    13, \
    12, \
    11, \
    10, \
    9, \
    8, \
    7, \
    6, \
    5, \
    4, \
    3, \
    2, \
    1, \
    0)
#define _FOR_JSON_COUNT_NN(...) _FOR_JSON_COUNT_NN_WITH_0(DUMMY, ##__VA_ARGS__)

#define _FOR_JSON_0(POP_N) _FOR_JSON_0_##POP_N
#define _FOR_JSON_1(POP_N) _FOR_JSON_1_##POP_N
#define _FOR_JSON_2(POP_N) _FOR_JSON_2_##POP_N
#define _FOR_JSON_3(POP_N) _FOR_JSON_3_##POP_N
#define _FOR_JSON_4(POP_N) _FOR_JSON_4_##POP_N
#define _FOR_JSON_5(POP_N) _FOR_JSON_5_##POP_N
#define _FOR_JSON_6(POP_N) _FOR_JSON_6_##POP_N
#define _FOR_JSON_7(POP_N) _FOR_JSON_7_##POP_N
#define _FOR_JSON_8(POP_N) _FOR_JSON_8_##POP_N
#define _FOR_JSON_9(POP_N) _FOR_JSON_9_##POP_N
#define _FOR_JSON_10(POP_N) _FOR_JSON_10_##POP_N
#define _FOR_JSON_11(POP_N) _FOR_JSON_11_##POP_N
#define _FOR_JSON_12(POP_N) _FOR_JSON_12_##POP_N
#define _FOR_JSON_13(POP_N) _FOR_JSON_13_##POP_N
#define _FOR_JSON_14(POP_N) _FOR_JSON_14_##POP_N
#define _FOR_JSON_15(POP_N) _FOR_JSON_15_##POP_N
#define _FOR_JSON_16(POP_N) _FOR_JSON_16_##POP_N
#define _FOR_JSON_17(POP_N) _FOR_JSON_17_##POP_N
#define _FOR_JSON_18(POP_N) _FOR_JSON_18_##POP_N
#define _FOR_JSON_19(POP_N) _FOR_JSON_19_##POP_N
#define _FOR_JSON_20(POP_N) _FOR_JSON_20_##POP_N
#define _FOR_JSON_21(POP_N) _FOR_JSON_21_##POP_N
#define _FOR_JSON_22(POP_N) _FOR_JSON_22_##POP_N
#define _FOR_JSON_23(POP_N) _FOR_JSON_23_##POP_N
#define _FOR_JSON_24(POP_N) _FOR_JSON_24_##POP_N
#define _FOR_JSON_25(POP_N) _FOR_JSON_25_##POP_N
#define _FOR_JSON_26(POP_N) _FOR_JSON_26_##POP_N
#define _FOR_JSON_27(POP_N) _FOR_JSON_27_##POP_N
#define _FOR_JSON_28(POP_N) _FOR_JSON_28_##POP_N
#define _FOR_JSON_29(POP_N) _FOR_JSON_29_##POP_N
#define _FOR_JSON_30(POP_N) _FOR_JSON_30_##POP_N

// FOREACH macro machinery for forwarding to single arg macros
#define _FOR_JSON_0_POP1(FUNC, TYPE)
#define _FOR_JSON_1_POP1(FUNC, TYPE, ARG1) _FOR_JSON_FINAL(FUNC, TYPE, ARG1)
#define _FOR_JSON_2_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_1_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_3_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_2_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_4_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_3_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_5_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_4_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_6_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_5_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_7_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_6_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_8_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_7_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_9_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_8_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_10_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_9_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_11_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_10_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_12_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_11_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_13_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_12_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_14_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_13_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_15_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_14_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_16_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_15_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_17_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_16_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_18_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_17_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_19_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_18_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_20_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_19_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_21_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_20_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_22_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_21_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_23_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_22_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_24_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_23_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_25_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_24_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_26_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_25_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_27_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_26_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_28_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_27_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_29_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_28_POP1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_30_POP1(FUNC, TYPE, ARG1, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1) \
  _FOR_JSON_29_POP1(FUNC, TYPE, ##__VA_ARGS__)

// FOREACH macro machinery for forwarding to double arg macros
#define _FOR_JSON_0_POP2(FUNC, TYPE)
#define _FOR_JSON_1_POP2(FUNC, TYPE, ARG1) INVALID_ODD_ARGS
#define _FOR_JSON_2_POP2(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_FINAL(FUNC, TYPE, ARG1, ARG2)
#define _FOR_JSON_3_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_4_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_2_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_5_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_6_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_4_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_7_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_8_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_6_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_9_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_10_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_8_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_11_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_12_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_10_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_13_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_14_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_12_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_15_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_16_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_14_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_17_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_18_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_16_POP2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_19_POP2(FUNC, TYPE, ARG1, ARG2, ...) INVALID_ODD_ARGS
#define _FOR_JSON_20_POP2(FUNC, TYPE, ARG1, ARG2, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, ARG1, ARG2) \
  _FOR_JSON_18_POP2(FUNC, TYPE, ##__VA_ARGS__)

// Forwarders for macros produced by the machinery above
#define _FOR_JSON_NEXT(FUNC, ...) FUNC##_FOR_JSON_NEXT(__VA_ARGS__)
#define _FOR_JSON_FINAL(FUNC, ...) FUNC##_FOR_JSON_FINAL(__VA_ARGS__)

#define WRITE_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD) \
  { \
    j[JSON_FIELD] = t.C_FIELD; \
  }
#define WRITE_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL(TYPE, C_FIELD, JSON_FIELD) \
  WRITE_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD)

#define WRITE_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  WRITE_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define WRITE_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  WRITE_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL(TYPE, FIELD, #FIELD)

#define WRITE_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD) \
  { \
    if (t.C_FIELD != t_default.C_FIELD) \
    { \
      j[JSON_FIELD] = t.C_FIELD; \
    } \
  }
#define WRITE_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL(TYPE, C_FIELD, JSON_FIELD) \
  WRITE_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD)

#define WRITE_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  WRITE_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define WRITE_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  WRITE_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL(TYPE, FIELD, #FIELD)

#define READ_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD) \
  { \
    const auto it = j.find(JSON_FIELD); \
    if (it == j.end()) \
    { \
      throw JsonParseError( \
        "Missing required field '" JSON_FIELD "' in object: " + j.dump()); \
    } \
    try \
    { \
      t.C_FIELD = it->get<decltype(TYPE::C_FIELD)>(); \
    } \
    catch (JsonParseError & jpe) \
    { \
      jpe.pointer_elements.push_back(JSON_FIELD); \
      throw; \
    } \
  }
#define READ_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL(TYPE, C_FIELD, JSON_FIELD) \
  READ_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD)

#define READ_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  READ_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define READ_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  READ_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL(TYPE, FIELD, #FIELD)

#define READ_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD) \
  { \
    const auto it = j.find(JSON_FIELD); \
    if (it != j.end()) \
    { \
      t.C_FIELD = it->get<decltype(TYPE::C_FIELD)>(); \
    } \
  }
#define READ_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL(TYPE, C_FIELD, JSON_FIELD) \
  READ_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD)

#define READ_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  READ_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define READ_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  READ_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL(TYPE, FIELD, #FIELD)

#define FILL_SCHEMA_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT( \
  TYPE, C_FIELD, JSON_FIELD) \
  j["properties"][JSON_FIELD] = \
    ::ds::json::schema_element<decltype(TYPE::C_FIELD)>(); \
  j["required"].push_back(JSON_FIELD);
#define FILL_SCHEMA_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL( \
  TYPE, C_FIELD, JSON_FIELD) \
  FILL_SCHEMA_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD)

#define FILL_SCHEMA_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  FILL_SCHEMA_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define FILL_SCHEMA_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  FILL_SCHEMA_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL(TYPE, FIELD, #FIELD)

#define FILL_SCHEMA_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT( \
  TYPE, C_FIELD, JSON_FIELD) \
  j["properties"][JSON_FIELD] = \
    ::ds::json::schema_element<decltype(TYPE::C_FIELD)>();
#define FILL_SCHEMA_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL( \
  TYPE, C_FIELD, JSON_FIELD) \
  FILL_SCHEMA_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, C_FIELD, JSON_FIELD)

#define FILL_SCHEMA_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  FILL_SCHEMA_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define FILL_SCHEMA_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  FILL_SCHEMA_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL(TYPE, FIELD, #FIELD)

#define ADD_SCHEMA_COMPONENTS_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT( \
  TYPE, C_FIELD, JSON_FIELD) \
  j["properties"][JSON_FIELD] = \
    doc.template add_schema_component<decltype(TYPE::C_FIELD)>(); \
  j["required"].push_back(JSON_FIELD);
#define ADD_SCHEMA_COMPONENTS_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL( \
  TYPE, C_FIELD, JSON_FIELD) \
  ADD_SCHEMA_COMPONENTS_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT( \
    TYPE, C_FIELD, JSON_FIELD)

#define ADD_SCHEMA_COMPONENTS_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  ADD_SCHEMA_COMPONENTS_REQUIRED_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define ADD_SCHEMA_COMPONENTS_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  ADD_SCHEMA_COMPONENTS_REQUIRED_WITH_RENAMES_FOR_JSON_FINAL( \
    TYPE, FIELD, #FIELD)

#define ADD_SCHEMA_COMPONENTS_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT( \
  TYPE, C_FIELD, JSON_FIELD) \
  j["properties"][JSON_FIELD] = \
    doc.template add_schema_component<decltype(TYPE::C_FIELD)>();
#define ADD_SCHEMA_COMPONENTS_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL( \
  TYPE, C_FIELD, JSON_FIELD) \
  ADD_SCHEMA_COMPONENTS_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT( \
    TYPE, C_FIELD, JSON_FIELD)

#define ADD_SCHEMA_COMPONENTS_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  ADD_SCHEMA_COMPONENTS_OPTIONAL_WITH_RENAMES_FOR_JSON_NEXT(TYPE, FIELD, #FIELD)
#define ADD_SCHEMA_COMPONENTS_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  ADD_SCHEMA_COMPONENTS_OPTIONAL_WITH_RENAMES_FOR_JSON_FINAL( \
    TYPE, FIELD, #FIELD)

#define JSON_FIELD_FOR_JSON_NEXT(TYPE, FIELD) \
  JsonField<decltype(TYPE::FIELD)>{#FIELD},
#define JSON_FIELD_FOR_JSON_FINAL(TYPE, FIELD) \
  JsonField<decltype(TYPE::FIELD)> \
  { \
#    FIELD \
  }

/** Defines from_json, to_json, fill_json_schema, schema_name and
 * add_schema_components functions for struct/class types, converting member
 * fields to JSON elements and populating schema documents describing this
 * transformation. Missing elements will cause errors to be raised. This assumes
 * that from_json, to_json, are implemented for each member
 * field type, either manually or through these macros. Additionally, you will
 * need schema_name, fill_json_schema, and add_schema_components to be defined
 * for OpenAPI schema generation.
 * // clang-format off
 *  ie, the following must compile, for each foo in T:
 *    T t; nlohmann::json j, schema;
 *    j["foo"] = t.foo;
 *    t.foo = j["foo"].get<decltype(T::foo)>();
 *    fill_json_schema(schema, t);
 *    std::string s = schema_name(t.foo);
 * // clang-format on
 *
 * Optional fields will be inserted into the JSON object iff their value differs
 * from the value in a default-constructed instance of T. So if optional fields
 * are present, then T must be default-constructible and the optional fields
 * must be distinguishable (have operator!= defined)
 *
 * To use:
 *  - Declare struct as normal
 *  - Add DELARE_JSON_TYPE, or WITH_BASE or WITH_OPTIONAL variants as required
 *  - Add DECLARE_JSON_REQUIRED_FIELDS listing fields which must be present
 *  - If there are optional fields, add DECLARE_JSON_OPTIONAL_FIELDS
 *  - If the json and struct fields have different names, use WITH_RENAMES
 *
 * Examples:
 *  struct X
 *  {
 *   int a, b;
 *  };
 *  DECLARE_JSON_TYPE(X)
 *  DECLARE_JSON_REQUIRED_FIELDS(X, a, b)
 *
 *  Valid JSON:
 *   { "a": 42, "b": 100 }
 *   { "a": 42, "b": 100, "Unused": ["Anything"] }
 *  Invalid JSON:
 *   {}
 *   { "a": 42 }
 *   { "a": 42, "b": "Hello world" }
 *
 *  struct Y
 *  {
 *   bool c;
 *   std::string d;
 *  };
 *  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Y)
 *  DECLARE_JSON_REQUIRED_FIELDS(Y, c)
 *  DECLARE_JSON_OPTIONAL_FIELDS(Y, d)
 *
 *  Valid JSON:
 *   { "c": true }
 *   { "c": false, "d": "Hello" }
 *  Invalid JSON:
 *   { "d": "Hello" }
 *
 *  struct X_A : X
 *  {
 *   int m;
 *  };
 *  DECLARE_JSON_TYPE_WITH_BASE(X_A, X)
 *  DECLARE_JSON_REQUIRED_FIELDS(X_A, m)
 *
 *  Valid JSON:
 *   { "a": 42, "b": 100, "m": 101 }
 *  Invalid JSON:
 *   { "a": 42, "b": 100 }
 *   { "m": 101 }
 *
 *  struct X_B : X
 *  {
 *   int n;
 *  };
 *  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(X_B, X)
 *  DECLARE_JSON_REQUIRED_FIELDS(X_B) // NO additional required fields
 *  DECLARE_JSON_OPTIONAL_FIELDS(X_B, n)
 *
 *  Valid JSON:
 *   { "a": 42, "b": 100 }
 *   { "a": 42, "b": 100, "n": 101 }
 *  Invalid JSON:
 *   { "n": 101 }
 *
 *  struct Z
 *  {
 *   int snake_case;
 *   std::string s;
 *  };
 *  DECLARE_JSON_TYPE(Z);
 *  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
 *    Z, snake_case, camelCase, s, msg);
 *
 *  Valid JSON:
 *   { "camelCase": 42, "msg": "Hello" }
 *   (converts to and from struct {snake_case: 42, s: "Hello"})
 *
 */

#define DECLARE_JSON_TYPE_IMPL( \
  TYPE, \
  PRE_TO_JSON, \
  POST_TO_JSON, \
  PRE_FROM_JSON, \
  POST_FROM_JSON, \
  PRE_FILL_SCHEMA, \
  POST_FILL_SCHEMA, \
  PRE_ADD_SCHEMA, \
  POST_ADD_SCHEMA) \
  void to_json_required_fields(nlohmann::json& j, const TYPE& t); \
  void to_json_optional_fields(nlohmann::json& j, const TYPE& t); \
  void from_json_required_fields(const nlohmann::json& j, TYPE& t); \
  void from_json_optional_fields(const nlohmann::json& j, TYPE& t); \
  void fill_json_schema_required_fields(nlohmann::json& j, const TYPE*); \
  void fill_json_schema_optional_fields(nlohmann::json& j, const TYPE*); \
  template <typename T> \
  void add_schema_components_required_fields( \
    T& doc, nlohmann::json& j, const TYPE*); \
  template <typename T> \
  void add_schema_components_optional_fields( \
    T& doc, nlohmann::json& j, const TYPE*); \
  inline void to_json(nlohmann::json& j, const TYPE& t) \
  { \
    PRE_TO_JSON; \
    to_json_required_fields(j, t); \
    POST_TO_JSON; \
  } \
  inline void from_json(const nlohmann::json& j, TYPE& t) \
  { \
    PRE_FROM_JSON; \
    from_json_required_fields(j, t); \
    POST_FROM_JSON; \
  } \
  inline void fill_json_schema(nlohmann::json& j, const TYPE* t) \
  { \
    PRE_FILL_SCHEMA; \
    fill_json_schema_required_fields(j, t); \
    POST_FILL_SCHEMA; \
  } \
  inline std::string schema_name(const TYPE*) \
  { \
    return #TYPE; \
  } \
  template <typename T> \
  void add_schema_components(T& doc, nlohmann::json& j, const TYPE* t) \
  { \
    PRE_ADD_SCHEMA; \
    add_schema_components_required_fields(doc, j, t); \
    POST_ADD_SCHEMA; \
  }

#define DECLARE_JSON_TYPE(TYPE) DECLARE_JSON_TYPE_IMPL(TYPE, , , , , , , , )

#define DECLARE_JSON_TYPE_WITH_BASE(TYPE, BASE) \
  DECLARE_JSON_TYPE_IMPL( \
    TYPE, \
    to_json(j, static_cast<const BASE&>(t)), \
    , \
    from_json(j, static_cast<BASE&>(t)), \
    , \
    fill_json_schema(j, static_cast<const BASE*>(t)), \
    , \
    add_schema_components(doc, j, static_cast<const BASE*>(t)), )

#define DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(TYPE) \
  DECLARE_JSON_TYPE_IMPL( \
    TYPE, \
    , \
    to_json_optional_fields(j, t), \
    , \
    from_json_optional_fields(j, t), \
    , \
    fill_json_schema_optional_fields(j, t), \
    , \
    add_schema_components_optional_fields(doc, j, t))

#define DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(TYPE, BASE) \
  DECLARE_JSON_TYPE_IMPL( \
    TYPE, \
    to_json(j, static_cast<const BASE&>(t)), \
    to_json_optional_fields(j, t), \
    from_json(j, static_cast<BASE&>(t)), \
    from_json_optional_fields(j, t), \
    fill_json_schema(j, static_cast<const BASE*>(t)), \
    fill_json_schema_optional_fields(j, t), \
    add_schema_components(doc, j, static_cast<const BASE*>(t)), \
    add_schema_components_optional_fields(doc, j, t))

#define DECLARE_JSON_REQUIRED_FIELDS(TYPE, ...) \
  _Pragma("clang diagnostic push"); \
  _Pragma("clang diagnostic ignored \"-Wgnu-zero-variadic-macro-arguments\""); \
  inline void to_json_required_fields( \
    nlohmann::json& j, [[maybe_unused]] const TYPE& t) \
  { \
    if (!j.is_object()) \
    { \
      j = nlohmann::json::object(); \
    } \
    _FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)(WRITE_REQUIRED, TYPE, ##__VA_ARGS__) \
  } \
  inline void from_json_required_fields( \
    const nlohmann::json& j, [[maybe_unused]] TYPE& t) \
  { \
    if (!j.is_object()) \
    { \
      throw JsonParseError("Expected object, found: " + j.dump()); \
    } \
    _FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)(READ_REQUIRED, TYPE, ##__VA_ARGS__) \
  } \
  inline void fill_json_schema_required_fields( \
    nlohmann::json& j, [[maybe_unused]] const TYPE*) \
  { \
    j["type"] = "object"; \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP1)(FILL_SCHEMA_REQUIRED, TYPE, ##__VA_ARGS__) \
  } \
  template <typename T> \
  void add_schema_components_required_fields( \
    [[maybe_unused]] T& doc, nlohmann::json& j, [[maybe_unused]] const TYPE*) \
  { \
    j["type"] = "object"; \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP1)(ADD_SCHEMA_COMPONENTS_REQUIRED, TYPE, ##__VA_ARGS__); \
  } \
  _Pragma("clang diagnostic pop");

#define DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(TYPE, ...) \
  inline void to_json_required_fields(nlohmann::json& j, const TYPE& t) \
  { \
    if (!j.is_object()) \
    { \
      j = nlohmann::json::object(); \
    } \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(WRITE_REQUIRED_WITH_RENAMES, TYPE, ##__VA_ARGS__) \
  } \
  inline void from_json_required_fields(const nlohmann::json& j, TYPE& t) \
  { \
    if (!j.is_object()) \
    { \
      throw JsonParseError("Expected object, found: " + j.dump()); \
    } \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(READ_REQUIRED_WITH_RENAMES, TYPE, ##__VA_ARGS__) \
  } \
  inline void fill_json_schema_required_fields(nlohmann::json& j, const TYPE*) \
  { \
    j["type"] = "object"; \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(FILL_SCHEMA_REQUIRED_WITH_RENAMES, TYPE, ##__VA_ARGS__) \
  } \
  template <typename T> \
  void add_schema_components_required_fields( \
    T& doc, nlohmann::json& j, const TYPE*) \
  { \
    j["type"] = "object"; \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(ADD_SCHEMA_COMPONENTS_REQUIRED_WITH_RENAMES, TYPE, ##__VA_ARGS__); \
  }

#define DECLARE_JSON_OPTIONAL_FIELDS(TYPE, ...) \
  inline void to_json_optional_fields(nlohmann::json& j, const TYPE& t) \
  { \
    const TYPE t_default{}; \
    _FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)(WRITE_OPTIONAL, TYPE, ##__VA_ARGS__) \
  } \
  inline void from_json_optional_fields(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)(READ_OPTIONAL, TYPE, ##__VA_ARGS__) \
  } \
  inline void fill_json_schema_optional_fields(nlohmann::json& j, const TYPE*) \
  { \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP1)(FILL_SCHEMA_OPTIONAL, TYPE, ##__VA_ARGS__) \
  } \
  template <typename T> \
  void add_schema_components_optional_fields( \
    T& doc, nlohmann::json& j, const TYPE*) \
  { \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP1)(ADD_SCHEMA_COMPONENTS_OPTIONAL, TYPE, ##__VA_ARGS__); \
  }

#define DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(TYPE, ...) \
  inline void to_json_optional_fields(nlohmann::json& j, const TYPE& t) \
  { \
    const TYPE t_default{}; \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(WRITE_OPTIONAL_WITH_RENAMES, TYPE, ##__VA_ARGS__) \
  } \
  inline void from_json_optional_fields(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(READ_OPTIONAL_WITH_RENAMES, TYPE, ##__VA_ARGS__) \
  } \
  inline void fill_json_schema_optional_fields( \
    nlohmann::json& j, [[maybe_unused]] const TYPE*) \
  { \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(FILL_SCHEMA_OPTIONAL_WITH_RENAMES, TYPE, ##__VA_ARGS__) \
  } \
  template <typename T> \
  void add_schema_components_optional_fields( \
    T& doc, nlohmann::json& j, [[maybe_unused]] const TYPE*) \
  { \
    _FOR_JSON_COUNT_NN(__VA_ARGS__) \
    (POP2)(ADD_SCHEMA_COMPONENTS_OPTIONAL_WITH_RENAMES, TYPE, ##__VA_ARGS__); \
  }

// Enum conversion, based on NLOHMANN_JSON_SERIALIZE_ENUM, but less permissive
// (throws on unknown JSON values)
#define DECLARE_JSON_ENUM(TYPE, ...) \
  template <typename BasicJsonType> \
  inline void to_json(BasicJsonType& j, const TYPE& e) \
  { \
    static_assert(std::is_enum<TYPE>::value, #TYPE " must be an enum!"); \
    static const std::pair<TYPE, BasicJsonType> m[] = __VA_ARGS__; \
    auto it = std::find_if( \
      std::begin(m), \
      std::end(m), \
      [e](const std::pair<TYPE, BasicJsonType>& ej_pair) -> bool { \
        return ej_pair.first == e; \
      }); \
    if (it == std::end(m)) \
    { \
      throw JsonParseError(fmt::format( \
        "Value {} in enum " #TYPE " has no specified JSON conversion", \
        (size_t)e)); \
    } \
    j = it->second; \
  } \
  template <typename BasicJsonType> \
  inline void from_json(const BasicJsonType& j, TYPE& e) \
  { \
    static_assert(std::is_enum<TYPE>::value, #TYPE " must be an enum!"); \
    static const std::pair<TYPE, BasicJsonType> m[] = __VA_ARGS__; \
    auto it = std::find_if( \
      std::begin(m), \
      std::end(m), \
      [&j](const std::pair<TYPE, BasicJsonType>& ej_pair) -> bool { \
        return ej_pair.second == j; \
      }); \
    if (it == std::end(m)) \
    { \
      throw JsonParseError( \
        fmt::format("{} is not convertible to " #TYPE, j.dump())); \
    } \
    e = it->first; \
  } \
  inline std::string schema_name(const TYPE*) \
  { \
    return #TYPE; \
  } \
  inline void fill_enum_schema(nlohmann::json& j, const TYPE*) \
  { \
    static const std::pair<TYPE, nlohmann::json> m[] = __VA_ARGS__; \
    auto enums = nlohmann::json::array(); \
    for (const auto& p : m) \
    { \
      enums.push_back(p.second); \
    } \
    j["enum"] = enums; \
    j["type"] = "string"; \
  }

#pragma clang diagnostic pop
