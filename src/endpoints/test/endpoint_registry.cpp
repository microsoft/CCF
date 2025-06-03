// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "ccf/endpoint_registry.h"

#include "ccf/ds/logger.h"
#include "ds/nonstd.h"
#include "endpoint_utils.h"

#include <doctest/doctest.h>

using namespace ccf::endpoints;

std::optional<PathTemplateSpec> require_parsed_components(
  const std::string& s, const std::vector<std::string>& expected_components)
{
  std::optional<PathTemplateSpec> spec;
  REQUIRE_NOTHROW(spec = PathTemplateSpec::parse(s));

  if (expected_components.size() == 0)
  {
    REQUIRE(!spec.has_value());
  }
  else
  {
    REQUIRE(spec.has_value());
    REQUIRE(spec->template_component_names == expected_components);
  }

  return spec;
}

TEST_CASE("URL template parsing")
{
  ccf::logger::config::default_init();

  std::optional<PathTemplateSpec> parsed;
  std::string path;
  std::smatch match;

  for (const std::string prefix : {"", "/hello", "/foo/bar/baz"})
  {
    require_parsed_components(prefix + "/bob", {});
    require_parsed_components(prefix + "/{name}", {"name"});
    require_parsed_components(prefix + "/{name}/world", {"name"});

    auto parsed =
      require_parsed_components(prefix + "/{name}/{place}", {"name", "place"});

    path = prefix + "/alice/spain";
    REQUIRE(std::regex_match(path, match, parsed->template_regex));
    REQUIRE(match[1].str() == "alice");
    REQUIRE(match[2].str() == "spain");

    path = prefix + "/alice:jump/spain";
    REQUIRE_FALSE(std::regex_match(path, match, parsed->template_regex));
    path = prefix + "/alice/spain:jump";
    REQUIRE_FALSE(std::regex_match(path, match, parsed->template_regex));

    require_parsed_components(prefix + "/{name}:do", {"name"});
    require_parsed_components(prefix + "/{name}:do/world", {"name"});
    require_parsed_components(prefix + "/{name}:do/{place}", {"name", "place"});

    require_parsed_components(prefix + "/bob:{action}", {"action"});
    require_parsed_components(prefix + "/bob:{action}/world", {"action"});
    require_parsed_components(
      prefix + "/bob:{action}/{place}", {"action", "place"});

    require_parsed_components(prefix + "/{name}:{action}", {"name", "action"});
    require_parsed_components(
      prefix + "/{name}:{action}/world", {"name", "action"});

    parsed = require_parsed_components(
      prefix + "/{name}:{action}/{place}", {"name", "action", "place"});

    path = prefix + "/alice/spain";
    REQUIRE_FALSE(std::regex_match(path, match, parsed->template_regex));

    path = prefix + "/alice:jump/spain";
    REQUIRE(std::regex_match(path, match, parsed->template_regex));
    REQUIRE(match[1].str() == "alice");
    REQUIRE(match[2].str() == "jump");
    REQUIRE(match[3].str() == "spain");
  }

  REQUIRE_THROWS(PathTemplateSpec::parse("/foo{id}"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/foo{id}bar"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/{id}bar"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/{id}-{name}"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/id{id}"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/foo{id}:"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/foo{id}/bar"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/foo/{id}bar"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/foo/id{id}:bar"));

  REQUIRE_THROWS(PathTemplateSpec::parse("/{id}/{id}"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/foo/{id}/{id}"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/{id}/foo/{id}"));
  REQUIRE_THROWS(PathTemplateSpec::parse("/{id}/{id}/foo"));
}

TEST_CASE("camel_case" * doctest::test_suite("nonstd"))
{
  using ccf::endpoints::camel_case;
  {
    INFO("Default separator");
    REQUIRE(camel_case("") == "");
    REQUIRE(camel_case("abc") == "Abc");
    REQUIRE(camel_case("abc", false) == "abc");

    REQUIRE(camel_case("hello world") == "HelloWorld");
    REQUIRE(camel_case("hello world", false) == "helloWorld");

    REQUIRE(
      camel_case("standard_snake_case_value") == "StandardSnakeCaseValue");
    REQUIRE(
      camel_case("standard_snake_case_value", false) ==
      "standardSnakeCaseValue");

    REQUIRE(
      camel_case("camel-with.many/many!many_many,many|many$separators") ==
      "CamelWithManyManyManyManyManyManySeparators");
    REQUIRE(
      camel_case(
        "camel-with.many/many!many_many,many|many$separators", false) ==
      "camelWithManyManyManyManyManyManySeparators");

    REQUIRE(camel_case("1handling2of3.numbers") == "1handling2of3Numbers");
    REQUIRE(
      camel_case("1handling2of3.numbers", false) == "1handling2of3Numbers");

    REQUIRE(
      camel_case("camel_With-Existing_mixed-casing_Is-1Perhaps_2Surprising") ==
      "Camel_With-ExistingMixedCasing_Is-1Perhaps_2Surprising");
    REQUIRE(
      camel_case(
        "camel_With-Existing_mixed-casing_Is-1Perhaps_2Surprising", false) ==
      "camel_With-ExistingMixedCasing_Is-1Perhaps_2Surprising");
  }
  {
    INFO("Custom separators");
    REQUIRE(camel_case("hello world", true, "_") == "Hello world");
    REQUIRE(camel_case("hello world", false, "_") == "hello world");

    REQUIRE(camel_case("hello_world", true, "_") == "HelloWorld");
    REQUIRE(camel_case("hello_world", false, "_") == "helloWorld");

    REQUIRE(
      camel_case("what-about-/mixed/separators", true, "-") ==
      "WhatAbout-/mixed/separators");
    REQUIRE(
      camel_case("what-about-/mixed/separators", false, "-") ==
      "whatAbout-/mixed/separators");

    REQUIRE(
      camel_case("what-about-/mixed/separators", true, "/") ==
      "What-about-MixedSeparators");
    REQUIRE(
      camel_case("what-about-/mixed/separators", false, "/") ==
      "what-about-MixedSeparators");
  }
}