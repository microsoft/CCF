// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <nlohmann/json.hpp>
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

/** Template specialisation must happen in the correct namespace, so
NAMESPACE_CONTAINS_JSON_TYPES must be stated within a namespace to use
DECLARE_REQUIRED_JSON_FIELDS.
*/
#define NAMESPACE_CONTAINS_JSON_TYPES \
  template <typename T> \
  struct RequiredJsonFields : std::false_type \
  {}; \
\
  template <typename T> \
  struct OptionalJsonFields : std::false_type \
  {}; \
\
  template <typename T, bool Required> \
  void write_fields(nlohmann::json& j, const T& t); \
\
  template <typename T, bool Required> \
  void read_fields(const nlohmann::json& j, T& t); \
\
  template <typename T> \
  void fill_enum_schema(nlohmann::json& schema); \
\
  template < \
    typename T, \
    typename = std::enable_if_t<RequiredJsonFields<T>::value>> \
  inline void to_json(nlohmann::json& j, const T& t) \
  { \
    j = nlohmann::json::object(); \
    write_fields<T, true>(j, t); \
    if constexpr (OptionalJsonFields<T>::value) \
    { \
      write_fields<T, false>(j, t); \
    } \
  } \
\
  template < \
    typename T, \
    typename = std::enable_if_t<RequiredJsonFields<T>::value>> \
  inline void from_json(const nlohmann::json& j, T& t) \
  { \
    if (!j.is_object()) \
    { \
      throw JsonParseError("Expected object, found: " + j.dump()); \
    } \
    read_fields<T, true>(j, t); \
    if constexpr (OptionalJsonFields<T>::value) \
    { \
      read_fields<T, false>(j, t); \
    } \
  }

/** Global namespace and ccf namespace are initialised here
 */
NAMESPACE_CONTAINS_JSON_TYPES;

namespace ccf
{
  NAMESPACE_CONTAINS_JSON_TYPES;
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

#define WRITE_BASIC_FOR_JSON_NEXT(TYPE, FIELD) j[#FIELD] = t.FIELD;
#define WRITE_BASIC_FOR_JSON_FINAL(TYPE, FIELD) \
  WRITE_BASIC_FOR_JSON_NEXT(TYPE, FIELD)

#define READ_BASIC_FOR_JSON_NEXT(TYPE, FIELD) \
  t.FIELD = j[#FIELD].get<decltype(TYPE::FIELD)>();
#define READ_BASIC_FOR_JSON_FINAL(TYPE, FIELD) \
  READ_BASIC_FOR_JSON_NEXT(TYPE, FIELD)

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

/** Defines from and to json functions for nlohmann::json with error messages on
 * missing elements. Can then use OPTIONAL variant to add non-required fields.
 * Only the given class members are considered. Example:
 *
 * struct X
 * {
 *  int a,b;
 * };
 * DECLARE_REQUIRED_JSON_FIELDS(X, a, b)
 */
#define DECLARE_REQUIRED_JSON_FIELDS(TYPE, ...) \
  template <> \
  struct RequiredJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto required_fields = std::make_tuple( \
      _FOR_JSON_NN(__VA_ARGS__)(JSON_FIELD, TYPE, ##__VA_ARGS__)); \
  }; \
  template <> \
  inline void write_fields<TYPE, true>(nlohmann::json & j, const TYPE& t) \
  { \
    _FOR_JSON_NN(__VA_ARGS__)(WRITE_REQUIRED, TYPE, ##__VA_ARGS__) \
  } \
  template <> \
  inline void read_fields<TYPE, true>(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_JSON_NN(__VA_ARGS__)(READ_REQUIRED, TYPE, ##__VA_ARGS__) \
  }

/** Defines from and to json functions for nlohmann::json with respect to a base
 * class. Example:
 *
 * struct X
 * {
 *  int a,b;
 * };
 * DECLARE_REQUIRED_JSON_FIELDS(X, a, b)
 *
 * struct Y : public X
 * {
 *  string c;
 * };
 * DECLARE_REQUIRED_JSON_FIELDS_WITH_BASE(Y, X, c)
 *
 * This is equivalent to:
 * DECLARE_REQUIRED_JSON_FIELDS(Y, a, b, c)
 */
#define DECLARE_REQUIRED_JSON_FIELDS_WITH_BASE(TYPE, BASE, ...) \
  template <> \
  struct RequiredJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto required_fields = std::tuple_cat( \
      RequiredJsonFields<BASE>::required_fields, \
      std::make_tuple( \
        _FOR_JSON_NN(__VA_ARGS__)(JSON_FIELD, TYPE, ##__VA_ARGS__))); \
  }; \
  template <> \
  inline void write_fields<TYPE, true>(nlohmann::json & j, const TYPE& t) \
  { \
    write_fields<BASE, true>(j, t); \
    _FOR_JSON_NN(__VA_ARGS__)(WRITE_REQUIRED, TYPE, ##__VA_ARGS__) \
  } \
  template <> \
  inline void read_fields<TYPE, true>(const nlohmann::json& j, TYPE& t) \
  { \
    read_fields<BASE, true>(j, t); \
    _FOR_JSON_NN(__VA_ARGS__)(READ_REQUIRED, TYPE, ##__VA_ARGS__) \
  }

/** Extends existing from and to json functions for nlohmann::json.
 * DECLARE_REQUIRED must already have been called for this type.
 * When converting from json, missing optional fields will not cause an error
 * and the field will be left with its default value.
 * When converting to json, the field will only be written if its value differs
 * from the default.
 *
 * struct X
 * {
 *  int a,b,c,d;
 * };
 * DECLARE_REQUIRED_JSON_FIELDS(X, a, b)
 * DECLARE_OPTIONAL_JSON_FIELDS(X, a, b, c, d)
 */
#define DECLARE_OPTIONAL_JSON_FIELDS(TYPE, ...) \
  template <> \
  struct OptionalJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto optional_fields = std::make_tuple( \
      _FOR_JSON_NN(__VA_ARGS__)(JSON_FIELD, TYPE, ##__VA_ARGS__)); \
  }; \
  template <> \
  inline void write_fields<TYPE, false>(nlohmann::json & j, const TYPE& t) \
  { \
    const TYPE t_default{}; \
    { \
      _FOR_JSON_NN(__VA_ARGS__)(WRITE_OPTIONAL, TYPE, ##__VA_ARGS__) \
    } \
  } \
  template <> \
  inline void read_fields<TYPE, false>(const nlohmann::json& j, TYPE& t) \
  { \
    { \
      _FOR_JSON_NN(__VA_ARGS__)(READ_OPTIONAL, TYPE, ##__VA_ARGS__) \
    } \
  }

/** Extends existing from and to json functions for nlohmann::json with respect
 * to a base class.
 */
#define DECLARE_OPTIONAL_JSON_FIELDS_WITH_BASE(TYPE, BASE, ...) \
  template <> \
  struct OptionalJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto optional_fields = std::tuple_cat( \
      OptionalJsonFields<BASE>::optional_fields, \
      std::make_tuple( \
        _FOR_JSON_NN(__VA_ARGS__)(JSON_FIELD, TYPE, ##__VA_ARGS__))); \
  }; \
  template <> \
  inline void write_fields<TYPE, false>(nlohmann::json & j, const TYPE& t) \
  { \
    const TYPE t_default{}; \
    write_fields<BASE, false>(j, t); \
    { \
      _FOR_JSON_NN(__VA_ARGS__)(WRITE_OPTIONAL, TYPE, ##__VA_ARGS__) \
    } \
  } \
  template <> \
  inline void read_fields<TYPE, false>(const nlohmann::json& j, TYPE& t) \
  { \
    read_fields<BASE, false>(j, t); \
    { \
      _FOR_JSON_NN(__VA_ARGS__)(READ_OPTIONAL, TYPE, ##__VA_ARGS__) \
    } \
  }

/** Defines simple from and to json functions for nlohmann::json.
 * Every class that is to be read from Lua needs to have these.
 * Only the given class members are considered. Example:
 *
 * struct X
 * {
 *  int a,b;
 * };
 * ADD_JSON_TRANSLATORS(X, a, b)
 */
#define ADD_JSON_TRANSLATORS(TYPE, ...) \
  inline void from_json(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_JSON_NN(__VA_ARGS__)(READ_BASIC, TYPE, ##__VA_ARGS__) \
  } \
  inline void to_json(nlohmann::json& j, const TYPE& t) \
  { \
    _FOR_JSON_NN(__VA_ARGS__)(WRITE_BASIC, TYPE, ##__VA_ARGS__) \
  }

/** Defines simple from and to json functions for nlohmann::json with respect to
 * a base class. Example:
 *
 * struct X
 * {
 *  int a,b;
 * };
 * ADD_JSON_TRANSLATORS(X, a, b)
 *
 * struct Y
 * {
 *  string c;
 * };
 * ADD_JSON_TRANSLATORS_WITH_BASE(Y, X, c)
 *
 * This is equivalent to:
 * ADD_JSON_TRANSLATORS(Y, a, b, c)
 */
#define ADD_JSON_TRANSLATORS_WITH_BASE(TYPE, B, ...) \
  inline void from_json(const nlohmann::json& j, TYPE& t) \
  { \
    from_json(j, static_cast<B&>(t)); \
    _FOR_JSON_NN(__VA_ARGS__)(READ_BASIC, TYPE, ##__VA_ARGS__) \
  } \
  inline void to_json(nlohmann::json& j, const TYPE& t) \
  { \
    to_json(j, static_cast<const B&>(t)); \
    _FOR_JSON_NN(__VA_ARGS__)(WRITE_BASIC, TYPE, ##__VA_ARGS__) \
  }

#define DECLARE_JSON_ENUM(TYPE, ...) \
  NLOHMANN_JSON_SERIALIZE_ENUM(TYPE, __VA_ARGS__) \
  template <> \
  inline void fill_enum_schema<TYPE>(nlohmann::json & schema) \
  { \
    static const std::pair<TYPE, nlohmann::json> m[] = __VA_ARGS__; \
    auto enums = nlohmann::json::array(); \
    for (const auto& p : m) \
    { \
      enums.push_back(p.second); \
    } \
    schema["enum"] = enums; \
  }
