#include "ds/json.h"
#include "ds/json_schema.h"

#include <array>
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>


#define __FOR_N( \
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
  _FOR_##N
#define _FOR_N(args...) \
  __FOR_N( \
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

#define READ_REQUIRED_FOR_NEXT(TYPE, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it == j.end()) \
    { \
      throw std::invalid_argument( \
        "Missing required field '" #FIELD "' in object: " + j.dump()); \
    } \
    t.FIELD = it->get<decltype(TYPE::FIELD)>(); \
  }
#define READ_REQUIRED_FOR_FINAL(TYPE, FIELD) READ_REQUIRED_FOR_NEXT(TYPE, FIELD)

#define READ_OPTIONAL_FOR_NEXT(TYPE, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it != j.end()) \
    { \
      t.FIELD = it->get<decltype(TYPE::FIELD)>(); \
    } \
  }
#define READ_OPTIONAL_FOR_FINAL(TYPE, FIELD) READ_OPTIONAL_FOR_NEXT(TYPE, FIELD)

#define JSON_FIELD_FOR_NEXT(TYPE, FIELD) \
  JsonField<decltype(TYPE::FIELD)>{#FIELD},
#define JSON_FIELD_FOR_FINAL(TYPE, FIELD) \
  JsonField<decltype(TYPE::FIELD)> \
  { \
#    FIELD \
  }

#define _FOR_FINAL(FUNC, TYPE, FIELD) FUNC##_FOR_FINAL(TYPE, FIELD)
#define _FOR_NEXT(FUNC, TYPE, FIELD) FUNC##_FOR_NEXT(TYPE, FIELD)

#define _FOR_1(FUNC, TYPE, FIELD) FUNC##_FOR_FINAL(TYPE, FIELD)
#define _FOR_2(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_1(FUNC, TYPE, PREV)
#define _FOR_3(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_2(FUNC, TYPE, FIELD, PREV)
#define _FOR_4(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_3(FUNC, TYPE, FIELD, PREV)
#define _FOR_5(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_4(FUNC, TYPE, FIELD, PREV)
#define _FOR_6(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_5(FUNC, TYPE, FIELD, PREV)
#define _FOR_7(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_6(FUNC, TYPE, FIELD, PREV)
#define _FOR_8(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_7(FUNC, TYPE, FIELD, PREV)
#define _FOR_9(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_8(FUNC, TYPE, FIELD, PREV)
#define _FOR_10(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_9(FUNC, TYPE, FIELD, PREV)
#define _FOR_11(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_10(FUNC, TYPE, FIELD, PREV)
#define _FOR_12(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_11(FUNC, TYPE, FIELD, PREV)
#define _FOR_13(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_12(FUNC, TYPE, FIELD, PREV)
#define _FOR_14(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_13(FUNC, TYPE, FIELD, PREV)
#define _FOR_15(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_14(FUNC, TYPE, FIELD, PREV)
#define _FOR_16(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_15(FUNC, TYPE, FIELD, PREV)
#define _FOR_17(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_16(FUNC, TYPE, FIELD, PREV)
#define _FOR_18(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_17(FUNC, TYPE, FIELD, PREV)
#define _FOR_19(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_18(FUNC, TYPE, FIELD, PREV)
#define _FOR_20(FUNC, TYPE, FIELD, PREV...) \
  _FOR_NEXT(FUNC, TYPE, FIELD) _FOR_19(FUNC, TYPE, FIELD, PREV)

#define DECLARE_REQUIRED_JSON_FIELDS(TYPE, FIELDS...) \
  template <> \
  void read_required_fields<TYPE>(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_N(FIELDS)(READ_REQUIRED, TYPE, FIELDS) \
  } \
  template <> \
  struct RequiredJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto required_fields = \
      std::make_tuple(_FOR_N(FIELDS)(JSON_FIELD, TYPE, FIELDS)); \
  };

#define DECLARE_OPTIONAL_JSON_FIELDS(TYPE, FIELDS...) \
  template <> \
  void read_optional_fields<TYPE>(const nlohmann::json& j, TYPE& t) \
  { \
    { \
      _FOR_N(FIELDS)(READ_OPTIONAL, TYPE, FIELDS) \
    } \
  } \
\
  template <> \
  struct OptionalJsonFields<TYPE> : std::true_type \
  { \
    static constexpr auto optional_fields = \
      std::make_tuple(_FOR_N(FIELDS)(JSON_FIELD, TYPE, FIELDS)); \
  };

struct Foo
{
  size_t a = {};
  std::string b = {};
};
DECLARE_REQUIRED_JSON_FIELDS(Foo, a, b);

std::ostream& operator<<(std::ostream& stream, const Foo& foo)
{
  stream << "a: " << foo.a << std::endl;
  stream << "b: " << foo.b << std::endl;
  return stream;
}

struct Bar
{
  size_t a = {};
  std::string b = {};
  size_t c = {};
};
DECLARE_REQUIRED_JSON_FIELDS(Bar, a);
DECLARE_OPTIONAL_JSON_FIELDS(Bar, b, c);

std::ostream& operator<<(std::ostream& stream, const Bar& bar)
{
  stream << "a: " << bar.a << std::endl;
  stream << "b: " << bar.b << std::endl;
  stream << "c: " << bar.c << std::endl;
  return stream;
}

int main(int argc, char** argv)
{
  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Foo foo = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << foo << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    j["unused"] = "Ignored";
    const Foo foo = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << foo << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["c"] = 34;
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;
  }

  {
    const auto foo_schema = build_schema<Foo>("Foo");
    std::cout << foo_schema.dump(2) << std::endl;
  }

  {
    const auto bar_schema = build_schema<Bar>("Bar");
    std::cout << bar_schema.dump(2) << std::endl;
  }

  return 0;
}
