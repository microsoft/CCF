#include <array>
#include <nlohmann/json.hpp>
#include <vector>

template <typename T>
struct RequiredJsonFieldsSpecified : std::false_type
{};

template <typename T>
struct OptionalJsonFieldsSpecified : std::false_type
{};

template <typename T>
void read_required_fields(const nlohmann::json& j, T& t);

template <typename T>
void read_optional_fields(const nlohmann::json& j, T& t);

template <
  typename T,
  typename = std::enable_if_t<RequiredJsonFieldsSpecified<T>::value>>
inline void from_json(const nlohmann::json& j, T& t)
{
  read_required_fields(j, t);

  if constexpr (OptionalJsonFieldsSpecified<T>::value)
  {
    read_optional_fields(j, t);
  }
}

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

#define READ_REQUIRED_1(FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it == j.end()) \
    { \
      throw std::invalid_argument( \
        "Missing required field '" #FIELD "' in object: " + j.dump()); \
    } \
    t.FIELD = it->get<decltype(TYPE::FIELD)>(); \
  }

#define _FOR_1(FUNC, a) FUNC##_FOR_1(a)
#define _FOR_2(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_1(FUNC, prev)
#define _FOR_3(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_2(FUNC, prev)
#define _FOR_4(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_3(FUNC, prev)
#define _FOR_5(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_4(FUNC, prev)
#define _FOR_6(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_5(FUNC, prev)
#define _FOR_7(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_6(FUNC, prev)
#define _FOR_8(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_7(FUNC, prev)
#define _FOR_9(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_8(FUNC, prev)
#define _FOR_10(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_9(FUNC, prev)
#define _FOR_11(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_10(FUNC, prev)
#define _FOR_12(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_11(FUNC, prev)
#define _FOR_13(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_12(FUNC, prev)
#define _FOR_14(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_13(FUNC, prev)
#define _FOR_15(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_14(FUNC, prev)
#define _FOR_16(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_15(FUNC, prev)
#define _FOR_17(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_16(FUNC, prev)
#define _FOR_18(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_17(FUNC, prev)
#define _FOR_19(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_18(FUNC, prev)
#define _FOR_20(FUNC, a, prev...) _FOR_1(FUNC, a) _FOR_19(FUNC, prev)

#define DECLARE_REQUIRED_JSON_FIELDS(TYPE, FIELDS...) \
  template <> \
  void read_required_fields<TYPE>(const nlohmann::json& j, TYPE& t) \
  { \
    _FOR_N(FIELDS)(READ_REQUIRED, FIELDS) \
  } \
  template <> \
  struct RequiredJsonFieldsSpecified<TYPE> : std::true_type \
  {};

#define DECLARE_OPTIONAL_JSON_FIELDS(TYPE, FIELD_Z) \
  template <> \
  void read_optional_fields<TYPE>(const nlohmann::json& j, TYPE& t) \
  { \
    { \
      const auto it = j.find(#FIELD_Z); \
      if (it != j.end()) \
      { \
        t.FIELD_Z = it->get<decltype(TYPE::FIELD_Z)>(); \
      } \
    } \
  } \
\
  template <> \
  struct OptionalJsonFieldsSpecified<TYPE> : std::true_type \
  {};

struct Foo
{
  size_t a;
  std::string b;
};
DECLARE_REQUIRED_JSON_FIELDS(Foo, a, b);

struct Bar
{
  size_t a;
  std::string b;
  size_t c;
};
DECLARE_REQUIRED_JSON_FIELDS(Bar, a);
//DECLARE_OPTIONAL_JSON_FIELDS(Bar, b, c);

int main(int argc, char** argv)
{
  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Foo foo = j;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    j["unused"] = "Ignored";
    const Foo foo = j;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    const Bar bar = j;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Bar bar = j;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["c"] = 34;
    const Bar bar = j;
  }

  return 0;
}

// struct FoundJsonFields
// {
//   std::vector <
// };

// template <typename Target, typename Spec>
// struct JsonValidator
// {
//   void from_json(const nlohmann::json& j)
//   {
//     for (const auto& required_field : Spec::required_fields)
//     {
//     }
//   }
// };
// struct RecordTag
// {
//   static constexpr auto name = "LOG_record";
// };