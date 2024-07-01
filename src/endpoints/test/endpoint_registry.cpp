// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "ccf/endpoint_registry.h"

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
    REQUIRE(std::regex_match(path, match, parsed->template_regex));
    REQUIRE(match[1].str() == "alice:jump");
    REQUIRE(match[2].str() == "spain");

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
