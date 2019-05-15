// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <nlohmann/json.hpp>

template <typename T>
void assign_j(T& o, const nlohmann::json& j)
{
  o = std::move(j.get<T>());
}

template <typename T>
struct RequiredJsonFields : std::false_type
{};

template <typename T>
struct OptionalJsonFields : std::false_type
{};

template <typename T>
struct JsonField
{
  char const* name;
};

template <typename T>
void write_required_fields(nlohmann::json& j, const T& t);

template <typename T>
void write_optional_fields(nlohmann::json& j, const T& t);

template <typename T, typename = std::enable_if_t<RequiredJsonFields<T>::value>>
inline void to_json(nlohmann::json& j, const T& t)
{
  write_required_fields(j, t);

  if constexpr (OptionalJsonFields<T>::value)
  {
    write_optional_fields(j, t);
  }
}

template <typename T>
void read_required_fields(const nlohmann::json& j, T& t);

template <typename T>
void read_optional_fields(const nlohmann::json& j, T& t);

template <typename T, typename = std::enable_if_t<RequiredJsonFields<T>::value>>
inline void from_json(const nlohmann::json& j, T& t)
{
  read_required_fields(j, t);

  if constexpr (OptionalJsonFields<T>::value)
  {
    read_optional_fields(j, t);
  }
}

#define __FOR_JSON_N( \
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
#define _FOR_JSON_N(args...) \
  __FOR_JSON_N( \
    args, \
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
    1)

#define _FOR_JSON_1(FUNC, TYPE, FIELD) FUNC##_FOR_JSON_FINAL(TYPE, FIELD)
#define _FOR_JSON_2(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_1(FUNC, TYPE, PREV)
#define _FOR_JSON_3(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_2(FUNC, TYPE, PREV)
#define _FOR_JSON_4(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_3(FUNC, TYPE, PREV)
#define _FOR_JSON_5(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_4(FUNC, TYPE, PREV)
#define _FOR_JSON_6(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_5(FUNC, TYPE, PREV)
#define _FOR_JSON_7(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_6(FUNC, TYPE, PREV)
#define _FOR_JSON_8(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_7(FUNC, TYPE, PREV)
#define _FOR_JSON_9(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_8(FUNC, TYPE, PREV)
#define _FOR_JSON_10(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_9(FUNC, TYPE, PREV)
#define _FOR_JSON_11(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_10(FUNC, TYPE, PREV)
#define _FOR_JSON_12(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_11(FUNC, TYPE, PREV)
#define _FOR_JSON_13(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_12(FUNC, TYPE, PREV)
#define _FOR_JSON_14(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_13(FUNC, TYPE, PREV)
#define _FOR_JSON_15(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_14(FUNC, TYPE, PREV)
#define _FOR_JSON_16(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_15(FUNC, TYPE, PREV)
#define _FOR_JSON_17(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_16(FUNC, TYPE, PREV)
#define _FOR_JSON_18(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_17(FUNC, TYPE, PREV)
#define _FOR_JSON_19(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_18(FUNC, TYPE, PREV)
#define _FOR_JSON_20(FUNC, TYPE, FIELD, PREV...) \
  _FOR_JSON_NEXT(FUNC, TYPE, FIELD) _FOR_JSON_19(FUNC, TYPE, PREV)

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
      throw std::invalid_argument( \
        "Missing required field '" #FIELD "' in object: " + j.dump()); \
    } \
    t.FIELD = it->get<decltype(TYPE::FIELD)>(); \
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

#define DECLARE_REQUIRED_JSON_FIELDS(TYPE, FIELDS...) \
  template <> \
  struct RequiredJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto required_fields = \
      std::make_tuple(_FOR_JSON_N(FIELDS)(JSON_FIELD, TYPE, FIELDS)); \
  }; \
  template <> \
  void write_required_fields<TYPE>(nlohmann::json & j, const TYPE& t) \
  { \
    _FOR_JSON_N(FIELDS)(WRITE_REQUIRED, TYPE, FIELDS) \
  } \
  template <> \
  void read_required_fields<TYPE>(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_JSON_N(FIELDS)(READ_REQUIRED, TYPE, FIELDS) \
  }

#define DECLARE_OPTIONAL_JSON_FIELDS(TYPE, FIELDS...) \
  template <> \
  struct OptionalJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto optional_fields = \
      std::make_tuple(_FOR_JSON_N(FIELDS)(JSON_FIELD, TYPE, FIELDS)); \
  }; \
  template <> \
  void write_optional_fields<TYPE>(nlohmann::json & j, const TYPE& t) \
  { \
    const TYPE t_default{}; \
    { \
      _FOR_JSON_N(FIELDS)(WRITE_OPTIONAL, TYPE, FIELDS) \
    } \
  } \
  template <> \
  void read_optional_fields<TYPE>(const nlohmann::json& j, TYPE& t) \
  { \
    { \
      _FOR_JSON_N(FIELDS)(READ_OPTIONAL, TYPE, FIELDS) \
    } \
  }

/** Defines from and to json functions for nlohmann::json.
 * Every class that is to be read from Lua needs to have these.
 * Only the given class members are considered. Example:
 *
 * struct X
 * {
 *  int a,b;
 * };
 * ADD_JSON_TRANSLATORS(X, a, b)
 *
 */
#define ADD_JSON_TRANSLATORS(C, attr...) \
  inline void from_json(const nlohmann::json& j, C& c) \
  { \
    _FOR_JSON_N(attr)(FROM_JSON, C, attr) \
  } \
  inline void to_json(nlohmann::json& j, const C& c) \
  { \
    _FOR_JSON_N(attr)(TO_JSON, C, attr) \
  }

/** Defines from and to json functions for nlohmann::json with respect to a base
 * class. Example:
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
#define ADD_JSON_TRANSLATORS_WITH_BASE(C, B, attr...) \
  inline void from_json(const nlohmann::json& j, C& c) \
  { \
    from_json(j, static_cast<B&>(c)); \
    _FOR_JSON_N(attr)(FROM_JSON, C, attr) \
  } \
  inline void to_json(nlohmann::json& j, const C& c) \
  { \
    to_json(j, static_cast<const B&>(c)); \
    _FOR_JSON_N(attr)(TO_JSON, C, attr) \
  }

// template <typename K, typename V>
// void to_json(nlohmann::json& j, const std::pair<K, V>& p)
// {
//   j = nlohmann::json::array({p.first, p.second});
// }

// template <typename K, typename V>
// void from_json(const nlohmann::json& j, std::pair<K, V>& p)
// {
//   assert(j.is_array() && j.size() == 2);

//   p.first = j.at(0);
//   p.second = j.at(1);
// }