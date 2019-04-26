// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <nlohmann/json.hpp>

template <typename T>
void assign_j(T& o, const nlohmann::json& j)
{
  T t = j;
  o = std::move(t);
}

#define __JSON_N( \
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
  _JSON_##N
#define _JSON_N(args...) \
  __JSON_N( \
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

#define TO_JSON_1(a) j[#a] = c.a;
#define FROM_JSON_1(a) assign_j(c.a, j[#a]);

#define _JSON_1(dir, a) dir##_JSON_1(a)
#define _JSON_2(dir, a, prev...) _JSON_1(dir, a) _JSON_1(dir, prev)
#define _JSON_3(dir, a, prev...) _JSON_1(dir, a) _JSON_2(dir, prev)
#define _JSON_4(dir, a, prev...) _JSON_1(dir, a) _JSON_3(dir, prev)
#define _JSON_5(dir, a, prev...) _JSON_1(dir, a) _JSON_4(dir, prev)
#define _JSON_6(dir, a, prev...) _JSON_1(dir, a) _JSON_5(dir, prev)
#define _JSON_7(dir, a, prev...) _JSON_1(dir, a) _JSON_6(dir, prev)
#define _JSON_8(dir, a, prev...) _JSON_1(dir, a) _JSON_7(dir, prev)
#define _JSON_9(dir, a, prev...) _JSON_1(dir, a) _JSON_8(dir, prev)
#define _JSON_10(dir, a, prev...) _JSON_1(dir, a) _JSON_9(dir, prev)
#define _JSON_11(dir, a, prev...) _JSON_1(dir, a) _JSON_10(dir, prev)
#define _JSON_12(dir, a, prev...) _JSON_1(dir, a) _JSON_11(dir, prev)
#define _JSON_13(dir, a, prev...) _JSON_1(dir, a) _JSON_12(dir, prev)
#define _JSON_14(dir, a, prev...) _JSON_1(dir, a) _JSON_13(dir, prev)
#define _JSON_15(dir, a, prev...) _JSON_1(dir, a) _JSON_14(dir, prev)
#define _JSON_16(dir, a, prev...) _JSON_1(dir, a) _JSON_15(dir, prev)
#define _JSON_17(dir, a, prev...) _JSON_1(dir, a) _JSON_16(dir, prev)
#define _JSON_18(dir, a, prev...) _JSON_1(dir, a) _JSON_17(dir, prev)
#define _JSON_19(dir, a, prev...) _JSON_1(dir, a) _JSON_18(dir, prev)
#define _JSON_20(dir, a, prev...) _JSON_1(dir, a) _JSON_19(dir, prev)

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
    _JSON_N(attr)(FROM, attr) \
  } \
  inline void to_json(nlohmann::json& j, const C& c) \
  { \
    _JSON_N(attr)(TO, attr) \
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
    _JSON_N(attr)(FROM, attr) \
  } \
  inline void to_json(nlohmann::json& j, const C& c) \
  { \
    to_json(j, static_cast<const B&>(c)); \
    _JSON_N(attr)(TO, attr) \
  }

template <typename K, typename V>
void to_json(nlohmann::json& j, const std::pair<K, V>& p)
{
  j = nlohmann::json::array({p.first, p.second});
}

template <typename K, typename V>
void from_json(const nlohmann::json& j, std::pair<K, V>& p)
{
  assert(j.is_array() && j.size() == 2);

  p.first = j.at(0);
  p.second = j.at(1);
}