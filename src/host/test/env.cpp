// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/env.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

TEST_CASE("envvars" * doctest::test_suite("env"))
{
  {
    INFO("Expand environment variable");

    std::string test_value("test_value");
    ::setenv("TEST_ENV_VAR", test_value.c_str(), 1);

    REQUIRE("" == ccf::env::expand_envvar(""));
    REQUIRE("not an env var" == ccf::env::expand_envvar("not an env var"));
    REQUIRE("$ENV_VAR_NOT_SET" == ccf::env::expand_envvar("$ENV_VAR_NOT_SET"));
    REQUIRE(test_value == ccf::env::expand_envvar("$TEST_ENV_VAR"));

    // ${} syntax is not supported
    REQUIRE(
      "${ENV_VAR_NOT_SET}" == ccf::env::expand_envvar("${ENV_VAR_NOT_SET}"));
  }
  {
    INFO("Expand path");

    std::string test_value1("test_value1");
    ::setenv("TEST_ENV_VAR1", test_value1.c_str(), 1);
    std::string test_value2("test_value2");
    ::setenv("TEST_ENV_VAR2", test_value2.c_str(), 1);

    REQUIRE("" == ccf::env::expand_envvars_in_path(""));
    REQUIRE("foo" == ccf::env::expand_envvars_in_path("foo"));
    REQUIRE("foo/" == ccf::env::expand_envvars_in_path("foo/"));
    REQUIRE("foo/bar" == ccf::env::expand_envvars_in_path("foo/bar"));
    REQUIRE("/" == ccf::env::expand_envvars_in_path("/"));
    REQUIRE("/foo" == ccf::env::expand_envvars_in_path("/foo"));
    REQUIRE("/foo/" == ccf::env::expand_envvars_in_path("/foo/"));
    REQUIRE("/foo/bar" == ccf::env::expand_envvars_in_path("/foo/bar"));

    REQUIRE(
      fmt::format("{}", test_value1) ==
      ccf::env::expand_envvars_in_path("$TEST_ENV_VAR1"));
    REQUIRE(
      fmt::format("{}/", test_value1) ==
      ccf::env::expand_envvars_in_path("$TEST_ENV_VAR1/"));
    REQUIRE(
      fmt::format("{}/{}", test_value1, test_value2) ==
      ccf::env::expand_envvars_in_path("$TEST_ENV_VAR1/$TEST_ENV_VAR2"));

    REQUIRE(
      fmt::format("/{}", test_value1) ==
      ccf::env::expand_envvars_in_path("/$TEST_ENV_VAR1"));
    REQUIRE(
      fmt::format("/{}/", test_value1) ==
      ccf::env::expand_envvars_in_path("/$TEST_ENV_VAR1/"));
    REQUIRE(
      fmt::format("/{}/{}", test_value1, test_value2) ==
      ccf::env::expand_envvars_in_path("/$TEST_ENV_VAR1/$TEST_ENV_VAR2"));
  }
}
