// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "ccf/endpoint_registry.h"

#include <doctest/doctest.h>

std::optional<ccf::endpoints::PathTemplateSpec> require_parsed_components(
  const std::string& s, const std::vector<std::string>& expected_components)
{
  using namespace ccf::endpoints;

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

TEST_CASE("Foo")
{
  logger::config::default_init();

  for (const std::string prefix : {"", "/hello", "/foo/bar/baz"})
  {
    require_parsed_components(prefix + "/bob", {});
    require_parsed_components(prefix + "/{name}", {"name"});
    require_parsed_components(prefix + "/{name}/world", {"name"});
    require_parsed_components(prefix + "/{name}/{place}", {"name", "place"});

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
    require_parsed_components(
      prefix + "/{name}:{action}/{place}", {"name", "action", "place"});
  }

  // ccf::endpoints::PathTemplateSpec::parse("/hello/what{name}ishappening/world");
  // ccf::endpoints::PathTemplateSpec::parse("/hello/{name}:ishappening/world");
}
