// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "json_schema.h"

#include <fmt/format_header_only.h>
#include <sstream>

template <typename T>
void assign_j(T& o, const nlohmann::json& j)
{
  o = std::move(j.get<T>());
}

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
    j = nlohmann::json::array();
    for (const auto& e : t)
    {
      j.push_back(e);
    }
  }

  template <typename T>
  inline void from_json(const nlohmann::json& j, std::vector<T>& t)
  {
    if (!j.is_array())
    {
      throw JsonParseError("Expected array, found: " + j.dump());
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

#define __FOR_JSON_NN( \
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
  N, \
  ...) \
  _FOR_JSON_##N
#define _FOR_JSON_WITH_0(...) \
  __FOR_JSON_NN( \
    __VA_ARGS__, \
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
#define _FOR_JSON_NN(...) _FOR_JSON_WITH_0(DUMMY, ##__VA_ARGS__)

#define _FOR_JSON_0(FUNC, TYPE)
#define _FOR_JSON_1(FUNC, TYPE, FIELD) FUNC##_FOR_JSON_FINAL(TYPE, FIELD)
#define _FOR_JSON_2(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_1(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_3(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_2(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_4(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_3(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_5(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_4(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_6(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_5(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_7(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_6(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_8(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_7(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_9(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_8(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_10(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_9(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_11(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_10(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_12(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_11(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_13(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_12(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_14(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_13(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_15(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_14(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_16(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_15(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_17(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_16(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_18(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_17(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_19(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_18(FUNC, TYPE, ##__VA_ARGS__)
#define _FOR_JSON_20(FUNC, TYPE, FIELD, ...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_19(FUNC, TYPE, ##__VA_ARGS__)

#define WRITE_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  { \
    j[#FIELD] = t.FIELD; \
  }
#define WRITE_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  WRITE_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD)

#define WRITE_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  { \
    if (t.FIELD != t_default.FIELD) \
    { \
      j[#FIELD] = t.FIELD; \
    } \
  }
#define WRITE_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  WRITE_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD)

#define READ_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it == j.end()) \
    { \
      throw JsonParseError( \
        "Missing required field '" #FIELD "' in object: " + j.dump()); \
    } \
    try \
    { \
      t.FIELD = it->get<decltype(TYPE::FIELD)>(); \
    } \
    catch (JsonParseError & jpe) \
    { \
      jpe.pointer_elements.push_back(#FIELD); \
      throw; \
    } \
  }
#define READ_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  READ_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD)

#define READ_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it != j.end()) \
    { \
      t.FIELD = it->get<decltype(TYPE::FIELD)>(); \
    } \
  }
#define READ_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  READ_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD)

#define FILL_SCHEMA_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  j["properties"][#FIELD] = \
    ::ds::json::schema_element<decltype(TYPE::FIELD)>(); \
  j["required"].push_back(#FIELD);
#define FILL_SCHEMA_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  FILL_SCHEMA_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD)

#define FILL_SCHEMA_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  j["properties"][#FIELD] = ::ds::json::schema_element<decltype(TYPE::FIELD)>();
#define FILL_SCHEMA_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  FILL_SCHEMA_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD)

#define JSON_FIELD_FOR_JSON_NEXT(TYPE, FIELD) \
  JsonField<decltype(TYPE::FIELD)>{#FIELD},
#define JSON_FIELD_FOR_JSON_FINAL(TYPE, FIELD) \
  JsonField<decltype(TYPE::FIELD)> \
  { \
#    FIELD \
  }

#define TO_JSON_FOR_JSON_NEXT(TYPE, FIELD) j[#FIELD] = c.FIELD;
#define TO_JSON_FOR_JSON_FINAL(TYPE, FIELD) TO_JSON_FOR_JSON_NEXT(TYPE, FIELD)

#define FROM_JSON_FOR_JSON_NEXT(TYPE, FIELD) \
  c.FIELD = j[#FIELD].get<decltype(TYPE::FIELD)>();
#define FROM_JSON_FOR_JSON_FINAL(TYPE, FIELD) \
  FROM_JSON_FOR_JSON_NEXT(TYPE, FIELD)

#define _FOR_JSON_NEXT(FUNC, TYPE, FIELD) FUNC##_FOR_JSON_NEXT(TYPE, FIELD)
#define _FOR_JSON_FINAL(FUNC, TYPE, FIELD) FUNC##_FOR_JSON_FINAL(TYPE, FIELD)

/** Defines from_json, to_json, and fill_json_schema functions for struct/class
 * types, converting member fields to JSON elements. Missing elements will cause
 * errors to be raised. This assumes that from_json, to_json, and
 * fill_json_schema are implemented for each member field type, either manually
 * or through these macros.
 *  ie, the following must compile, for each foo in T:
 *    T t; nlohmann::json j, schema;
 *    j["foo"] = t.foo;
 *    t.foo = j["foo"].get<decltype(T::foo)>();
 *    fill_json_schema(schema, t);
 * 
 * To use:
 *  - Declare struct as normal
 *  - Add DELARE_JSON_TYPE, or WITH_BASE or WITH_OPTIONAL variants as required
 *  - Add DECLARE_JSON_REQUIRED_FIELDS listing fields which must be present
 *  - If there are optional fields, add DECLARE_JSON_OPTIONAL_FIELDS
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
 */

#define DECLARE_JSON_TYPE_IMPL( \
  TYPE, \
  PRE_TO_JSON, \
  POST_TO_JSON, \
  PRE_FROM_JSON, \
  POST_FROM_JSON, \
  PRE_FILL_SCHEMA, \
  POST_FILL_SCHEMA) \
  void to_json_required_fields(nlohmann::json& j, const TYPE& t); \
  void to_json_optional_fields(nlohmann::json& j, const TYPE& t); \
  void from_json_required_fields(const nlohmann::json& j, TYPE& t); \
  void from_json_optional_fields(const nlohmann::json& j, TYPE& t); \
  void fill_json_schema_required_fields(nlohmann::json& j, const TYPE& t); \
  void fill_json_schema_optional_fields(nlohmann::json& j, const TYPE& t); \
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
  inline void fill_json_schema(nlohmann::json& j, const TYPE& t) \
  { \
    PRE_FILL_SCHEMA; \
    fill_json_schema_required_fields(j, t); \
    POST_FILL_SCHEMA; \
  }

#define DECLARE_JSON_TYPE(TYPE) DECLARE_JSON_TYPE_IMPL(TYPE, , , , , , )

#define DECLARE_JSON_TYPE_WITH_BASE(TYPE, BASE) \
  DECLARE_JSON_TYPE_IMPL( \
    TYPE, \
    to_json(j, static_cast<const BASE&>(t)), \
    , \
    from_json(j, static_cast<BASE&>(t)), \
    , \
    fill_json_schema(j, static_cast<const BASE&>(t)), )

#define DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(TYPE) \
  DECLARE_JSON_TYPE_IMPL( \
    TYPE, \
    , \
    to_json_optional_fields(j, t), \
    , \
    from_json_optional_fields(j, t), \
    , \
    fill_json_schema_optional_fields(j, t))

#define DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(TYPE, BASE) \
  DECLARE_JSON_TYPE_IMPL( \
    TYPE, \
    to_json(j, static_cast<const BASE&>(t)), \
    to_json_optional_fields(j, t), \
    from_json(j, static_cast<BASE&>(t)), \
    from_json_optional_fields(j, t), \
    fill_json_schema(j, static_cast<const BASE&>(t)), \
    fill_json_schema_optional_fields(j, t))

#define DECLARE_JSON_REQUIRED_FIELDS(TYPE, ...) \
  inline void to_json_required_fields(nlohmann::json& j, const TYPE& t) \
  { \
    if (!j.is_object()) \
    { \
      j = nlohmann::json::object(); \
    } \
    _FOR_JSON_NN(__VA_ARGS__)(WRITE_REQUIRED, TYPE, ##__VA_ARGS__) \
  } \
  inline void from_json_required_fields(const nlohmann::json& j, TYPE& t) \
  { \
    if (!j.is_object()) \
    { \
      throw JsonParseError("Expected object, found: " + j.dump()); \
    } \
    _FOR_JSON_NN(__VA_ARGS__)(READ_REQUIRED, TYPE, ##__VA_ARGS__) \
  } \
  inline void fill_json_schema_required_fields(nlohmann::json& j, const TYPE&) \
  { \
    j["type"] = "object"; \
    _FOR_JSON_NN(__VA_ARGS__)(FILL_SCHEMA_REQUIRED, TYPE, ##__VA_ARGS__) \
  }

#define DECLARE_JSON_OPTIONAL_FIELDS(TYPE, ...) \
  inline void to_json_optional_fields(nlohmann::json& j, const TYPE& t) \
  { \
    const TYPE t_default{}; \
    _FOR_JSON_NN(__VA_ARGS__)(WRITE_OPTIONAL, TYPE, ##__VA_ARGS__) \
  } \
  inline void from_json_optional_fields(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_JSON_NN(__VA_ARGS__)(READ_OPTIONAL, TYPE, ##__VA_ARGS__) \
  } \
  inline void fill_json_schema_optional_fields( \
    nlohmann::json& j, const TYPE& t) \
  { \
    _FOR_JSON_NN(__VA_ARGS__)(FILL_SCHEMA_OPTIONAL, TYPE, ##__VA_ARGS__) \
  }

#define DECLARE_JSON_ENUM(TYPE, ...) \
  NLOHMANN_JSON_SERIALIZE_ENUM(TYPE, __VA_ARGS__) \
  inline void fill_enum_schema(nlohmann::json& j, const TYPE&) \
  { \
    static const std::pair<TYPE, nlohmann::json> m[] = __VA_ARGS__; \
    auto enums = nlohmann::json::array(); \
    for (const auto& p : m) \
    { \
      enums.push_back(p.second); \
    } \
    j["enum"] = enums; \
  }
