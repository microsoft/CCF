// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../json_schema.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <nlohmann/json.hpp>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>
#include <vector>

struct Bar
{
  size_t a = {};
  std::string b = {};
  size_t c = {};
};
DECLARE_REQUIRED_JSON_FIELDS(Bar, a);
DECLARE_OPTIONAL_JSON_FIELDS(Bar, b, c);

TEST_CASE("basic macro parser generation")
{
  const Bar default_bar = {};
  nlohmann::json j;

  REQUIRE_THROWS_AS(j.get<Bar>(), std::invalid_argument);

  j["a"] = 42;

  const Bar bar_0 = j;
  REQUIRE(bar_0.a == j["a"]);
  REQUIRE(bar_0.b == default_bar.b);
  REQUIRE(bar_0.c == default_bar.c);

  j["b"] = "Test";
  j["c"] = 100;
  const Bar bar_1 = j;
  REQUIRE(bar_1.a == j["a"]);
  REQUIRE(bar_1.b == j["b"]);
  REQUIRE(bar_1.c == j["c"]);
}

struct Baz : public Bar
{
  size_t d = {};
  size_t e = {};
};
DECLARE_REQUIRED_JSON_FIELDS_WITH_BASE(Baz, Bar, d);
DECLARE_OPTIONAL_JSON_FIELDS_WITH_BASE(Baz, Bar, e);

TEST_CASE("macro parser generation with base classes")
{
  const Baz default_baz = {};
  nlohmann::json j;

  REQUIRE_THROWS_AS(j.get<Baz>(), std::invalid_argument);

  j["a"] = 42;

  REQUIRE_THROWS_AS(j.get<Baz>(), std::invalid_argument);

  j["d"] = 43;

  const Baz baz_0 = j;
  REQUIRE(baz_0.a == j["a"]);
  REQUIRE(baz_0.b == default_baz.b);
  REQUIRE(baz_0.c == default_baz.c);
  REQUIRE(baz_0.d == j["d"]);
  REQUIRE(baz_0.e == default_baz.e);

  j["b"] = "Test";
  j["c"] = 100;
  j["e"] = 101;
  const Baz baz_1 = j;
  REQUIRE(baz_1.a == j["a"]);
  REQUIRE(baz_1.b == j["b"]);
  REQUIRE(baz_1.c == j["c"]);
  REQUIRE(baz_1.d == j["d"]);
  REQUIRE(baz_1.e == j["e"]);
}

namespace ccf
{
  struct Foo
  {
    size_t n_0 = 42;
    size_t n_1 = 43;
    int i_0 = -1;
    int64_t i64_0 = -2;
    std::string s_0 = "Default value";
    std::string s_1 = "Other default value";
    std::optional<size_t> opt = std::nullopt;
    std::vector<std::string> vec_s = {};
    size_t ignored;
  };
  DECLARE_REQUIRED_JSON_FIELDS(Foo, n_0, i_0, i64_0, s_0);
  DECLARE_OPTIONAL_JSON_FIELDS(Foo, n_1, s_1, opt, vec_s);
}

TEST_CASE("schema generation")
{
  const auto schema = ccf::build_schema<ccf::Foo>("Foo");

  const auto properties_it = schema.find("properties");
  REQUIRE(properties_it != schema.end());

  const auto required_it = schema.find("required");
  REQUIRE(required_it != schema.end());

  REQUIRE(required_it->is_array());
  REQUIRE(required_it->size() == 4);

  // Check limits are actually achievable
  {
    auto j_max = nlohmann::json::object();
    auto j_min = nlohmann::json::object();
    for (const std::string& required : *required_it)
    {
      const auto property_it = properties_it->find(required);
      REQUIRE(property_it != properties_it->end());

      const auto type = property_it->at("type");
      if (type == "number")
      {
        j_min[required] = property_it->at("minimum");
        j_max[required] = property_it->at("maximum");
      }
      else if (type == "string")
      {
        j_min[required] = "Hello world";
        j_max[required] = "Hello world";
      }
      else
      {
        throw std::logic_error("Unsupported type");
      }
    }

    const auto foo_min = j_min.get<ccf::Foo>();
    const auto foo_max = j_max.get<ccf::Foo>();

    using size_limits = std::numeric_limits<size_t>;

    REQUIRE(foo_min.n_0 == size_limits::min());
    REQUIRE(foo_max.n_0 == size_limits::max());

    using int_limits = std::numeric_limits<int>;
    REQUIRE(foo_min.i_0 == int_limits::min());
    REQUIRE(foo_max.i_0 == int_limits::max());

    using int64_limits = std::numeric_limits<int64_t>;
    REQUIRE(foo_min.i64_0 == int64_limits::min());
    REQUIRE(foo_max.i64_0 == int64_limits::max());
  }
}

namespace ccf
{
  struct Nest0
  {
    size_t n = {};
  };
  DECLARE_REQUIRED_JSON_FIELDS(Nest0, n);

  bool operator==(const Nest0& l, const Nest0& r)
  {
    return l.n == r.n;
  }

  struct Nest1
  {
    Nest0 a = {};
    Nest0 b = {};
  };
  DECLARE_REQUIRED_JSON_FIELDS(Nest1, a, b);

  bool operator==(const Nest1& l, const Nest1& r)
  {
    return l.a == r.a && l.b == r.b;
  }

  struct Nest2
  {
    Nest1 x;
    std::vector<Nest1> xs;
  };
  DECLARE_REQUIRED_JSON_FIELDS(Nest2, x, xs);

  bool operator==(const Nest2& l, const Nest2& r)
  {
    return l.x == r.x && l.xs == r.xs;
  }

  struct Nest3
  {
    Nest2 v;
  };
  DECLARE_REQUIRED_JSON_FIELDS(Nest3, v);

  bool operator==(const Nest3& l, const Nest3& r)
  {
    return l.v == r.v;
  }
}

TEST_CASE("nested")
{
  using namespace ccf;
  const Nest0 n0_1{10};
  const Nest0 n0_2{20};
  const Nest0 n0_3{30};
  const Nest0 n0_4{40};

  const Nest1 n1_1{n0_1, n0_2};
  const Nest1 n1_2{n0_1, n0_3};
  const Nest1 n1_3{n0_1, n0_4};
  const Nest1 n1_4{n0_2, n0_3};
  const Nest1 n1_5{n0_3, n0_4};
  const Nest1 n1_6{n0_4, n0_4};

  const Nest2 n2_1{n1_1, {n1_6, n1_5, n1_4, n1_3, n1_2}};

  Nest3 n3{n2_1};

  nlohmann::json j = n3;
  const auto r0 = j.get<Nest3>();

  REQUIRE(n3 == r0);

  {
    auto invalid_json = j;
    invalid_json["v"]["xs"][3]["a"].erase("n");
    try
    {
      invalid_json.get<Nest3>();
    }
    catch (JsonParseError& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v/xs/3/a");
    }

    invalid_json["v"]["xs"][3].erase("a");
    try
    {
      invalid_json.get<Nest3>();
    }
    catch (JsonParseError& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v/xs/3");
    }

    invalid_json["v"]["xs"][3] = "Broken";
    try
    {
      invalid_json.get<Nest3>();
    }
    catch (JsonParseError& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v/xs/3");
    }

    invalid_json["v"]["xs"] = "Broken";
    try
    {
      invalid_json.get<Nest3>();
    }
    catch (JsonParseError& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v/xs");
    }

    invalid_json["v"].erase("xs");
    try
    {
      invalid_json.get<Nest3>();
    }
    catch (JsonParseError& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v");
    }
  }
}

namespace ccf
{
  struct EnumStruct
  {
    enum class SampleEnum
    {
      One,
      Two,
      Three
    };

    SampleEnum se;
  };

  DECLARE_JSON_ENUM(
    EnumStruct::SampleEnum,
    {{EnumStruct::SampleEnum::One, "one"},
     {EnumStruct::SampleEnum::Two, "two"},
     {EnumStruct::SampleEnum::Three, "three"}})
  DECLARE_REQUIRED_JSON_FIELDS(EnumStruct, se);
}

TEST_CASE("enum")
{
  using namespace ccf;

  EnumStruct es;
  es.se = EnumStruct::SampleEnum::Two;

  nlohmann::json j = es;

  REQUIRE(j["se"] == "two");

  const auto schema = build_schema<EnumStruct>("EnumStruct");

  const nlohmann::json expected{"one", "two", "three"};
  REQUIRE(schema["properties"]["se"]["enum"] == expected);
}
