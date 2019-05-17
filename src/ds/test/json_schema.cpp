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
