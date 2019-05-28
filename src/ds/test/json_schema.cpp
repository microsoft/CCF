// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../json_schema.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <nlohmann/json.hpp>
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
    std::string s_0 = "Default value";
    std::string s_1 = "Other default value";
    std::optional<size_t> opt = std::nullopt;
    std::vector<std::string> vec_s = {};
    size_t ignored;
  };
  DECLARE_REQUIRED_JSON_FIELDS(Foo, n_0, s_0);
  DECLARE_OPTIONAL_JSON_FIELDS(Foo, n_1, s_1, opt, vec_s);
}

TEST_CASE("schema generation")
{
  const auto schema = ccf::build_schema<ccf::Foo>("Foo");

  const auto required_it = schema.find("required");
  REQUIRE(required_it != schema.end());

  REQUIRE(required_it->is_array());
  REQUIRE(required_it->size() == 2);
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

  template <>
  struct RequiredJsonFields<Nest3> : std::true_type
  {
    static constexpr auto required_fields =
      std::make_tuple(JsonField<decltype(Nest3::v)>{"v"});
  };

  template <>
  inline void write_fields<Nest3, true>(nlohmann::json& j, const Nest3& t)
  {
    {
      j["v"] = t.v;
    }
  }

  template <>
  inline void read_fields<Nest3, true>(const nlohmann::json& j, Nest3& t)
  {
    {
      const auto it = j.find("v");
      if (it == j.end())
      {
        throw json_parse_error(
          "Missing required field '"
          "v"
          "' in object: " +
          j.dump());
      }
      try
      {
        t.v = it->get<decltype(Nest3::v)>();
      }
      catch (json_parse_error& jpe)
      {
        jpe.pointer_elements.push_back("v");
        throw;
      }
    }
  }

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
    catch (json_parse_error& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v/xs/a");
    }

    invalid_json["v"]["xs"][3].erase("a");
    try
    {
      invalid_json.get<Nest3>();
    }
    catch (json_parse_error& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v/xs");
    }

    invalid_json["v"]["xs"].erase(3);
    REQUIRE_NOTHROW(invalid_json.get<Nest3>());

    invalid_json["v"].erase("xs");
    try
    {
      invalid_json.get<Nest3>();
    }
    catch (json_parse_error& jpe)
    {
      REQUIRE(jpe.pointer() == "#/v");
    }
  }
}