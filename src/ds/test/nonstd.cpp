// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/nonstd.h"

#include <algorithm>
#include <doctest/doctest.h>
#include <stdlib.h>
#include <string>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

TEST_CASE("split" * doctest::test_suite("nonstd"))
{
  {
    INFO("Basic splits");
    const auto s = "Good afternoon, good evening, and good night!";

    {
      INFO("Split by spaces");
      auto v = ccf::nonstd::split(s, " ");
      REQUIRE(v.size() == 7);
      REQUIRE(v[0] == "Good");
      REQUIRE(v[1] == "afternoon,");
      REQUIRE(v[2] == "good");
      REQUIRE(v[3] == "evening,");
      REQUIRE(v[4] == "and");
      REQUIRE(v[5] == "good");
      REQUIRE(v[6] == "night!");
    }

    {
      INFO("Split by commas");
      auto v = ccf::nonstd::split(s, ",");
      REQUIRE(v.size() == 3);
      REQUIRE(v[0] == "Good afternoon");
      REQUIRE(v[1] == " good evening");
      REQUIRE(v[2] == " and good night!");
    }

    {
      INFO("Split by comma-with-space");
      auto v = ccf::nonstd::split(s, ", ");
      REQUIRE(v.size() == 3);
      REQUIRE(v[0] == "Good afternoon");
      REQUIRE(v[1] == "good evening");
      REQUIRE(v[2] == "and good night!");

      {
        INFO("split(max_splits=3)");
        {
          auto v = ccf::nonstd::split(s, " ", 3);
          // NB: max_splits=3 => 4 returned segments
          REQUIRE(v.size() == 4);
          REQUIRE(v[0] == "Good");
          REQUIRE(v[1] == "afternoon,");
          REQUIRE(v[2] == "good");
          REQUIRE(v[3] == "evening, and good night!");
        }

        {
          auto v = ccf::nonstd::split(s, "afternoon", 3);
          // NB: max_splits=3, but only 1 split possible => 2 returned segments
          REQUIRE(v.size() == 2);
          REQUIRE(v[0] == "Good ");
          REQUIRE(v[1] == ", good evening, and good night!");
        }
      }

      {
        INFO("split_1");
        auto t = ccf::nonstd::split_1(s, ", ");
        REQUIRE(std::get<0>(t) == "Good afternoon");
        REQUIRE(std::get<1>(t) == "good evening, and good night!");
      }
    }

    {
      INFO("Split by commas");
      auto v = ccf::nonstd::split(s, ",");
      REQUIRE(v.size() == 3);
      REQUIRE(v[0] == "Good afternoon");
      REQUIRE(v[1] == " good evening");
      REQUIRE(v[2] == " and good night!");
    }

    {
      INFO("Split by 'oo'");
      auto v = ccf::nonstd::split(s, "oo");
      REQUIRE(v.size() == 5);
      REQUIRE(v[0] == "G");
      REQUIRE(v[1] == "d aftern");
      REQUIRE(v[2] == "n, g");
      REQUIRE(v[3] == "d evening, and g");
      REQUIRE(v[4] == "d night!");
    }
  }

  {
    INFO("Edge cases");

    {
      const auto s = "  bob ";
      auto v = ccf::nonstd::split(s, " ");
      REQUIRE(v.size() == 4);
      REQUIRE(v[0].empty());
      REQUIRE(v[1].empty());
      REQUIRE(v[2] == "bob");
      REQUIRE(v[3].empty());
    }

    {
      const auto s = "bobbob";
      {
        auto v = ccf::nonstd::split(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0] == "bobbob");
      }

      {
        auto v = ccf::nonstd::split(s, "bob");
        REQUIRE(v.size() == 3);
        REQUIRE(v[0].empty());
        REQUIRE(v[1].empty());
        REQUIRE(v[2].empty());
      }

      {
        auto t = ccf::nonstd::split_1(s, "bob");
        REQUIRE(std::get<0>(t).empty());
        REQUIRE(std::get<1>(t) == "bob");
      }
    }

    {
      const auto s = "";
      {
        auto v = ccf::nonstd::split(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto v = ccf::nonstd::split(s, "bob");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto t = ccf::nonstd::split_1(s, " ");
        REQUIRE(std::get<0>(t).empty());
        REQUIRE(std::get<1>(t).empty());
      }
    }
  }
}

TEST_CASE("rsplit" * doctest::test_suite("nonstd"))
{
  {
    INFO("Basic rsplits");

    const auto s = "Good afternoon, good evening, and good night!";

    {
      INFO("rsplit by spaces");
      auto v = ccf::nonstd::rsplit(s, " ");
      REQUIRE(v.size() == 7);
      REQUIRE(v[0] == "night!");
      REQUIRE(v[1] == "good");
      REQUIRE(v[2] == "and");
      REQUIRE(v[3] == "evening,");
      REQUIRE(v[4] == "good");
      REQUIRE(v[5] == "afternoon,");
      REQUIRE(v[6] == "Good");
    }

    {
      INFO("rsplit(max_splits=3)");
      {
        auto v = ccf::nonstd::rsplit(s, " ", 3);
        // NB: max_splits=3 => 4 returned segments
        REQUIRE(v.size() == 4);
        REQUIRE(v[0] == "night!");
        REQUIRE(v[1] == "good");
        REQUIRE(v[2] == "and");
        REQUIRE(v[3] == "Good afternoon, good evening,");
      }

      {
        auto v = ccf::nonstd::rsplit(s, "afternoon", 3);
        // NB: max_splits=3, but only 1 split possible => 2 returned segments
        REQUIRE(v.size() == 2);
        REQUIRE(v[0] == ", good evening, and good night!");
        REQUIRE(v[1] == "Good ");
      }
    }

    {
      INFO("rsplit_1");
      auto t = ccf::nonstd::rsplit_1(s, ", ");
      REQUIRE(std::get<0>(t) == "Good afternoon, good evening");
      REQUIRE(std::get<1>(t) == "and good night!");
    }
  }

  {
    INFO("Edge cases");

    {
      const auto s = "  bob ";
      auto v = ccf::nonstd::rsplit(s, " ");
      REQUIRE(v.size() == 4);
      REQUIRE(v[0].empty());
      REQUIRE(v[1] == "bob");
      REQUIRE(v[2].empty());
      REQUIRE(v[3].empty());
    }

    {
      const auto s = "bobbob";
      {
        auto v = ccf::nonstd::rsplit(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0] == "bobbob");
      }

      {
        auto v = ccf::nonstd::rsplit(s, "bob");
        REQUIRE(v.size() == 3);
        REQUIRE(v[0].empty());
        REQUIRE(v[1].empty());
        REQUIRE(v[2].empty());
      }

      {
        auto t = ccf::nonstd::rsplit_1(s, "bob");
        REQUIRE(std::get<0>(t) == "bob");
        REQUIRE(std::get<1>(t).empty());
      }
    }

    {
      const auto s = "";
      {
        auto v = ccf::nonstd::rsplit(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto v = ccf::nonstd::rsplit(s, "bob");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto t = ccf::nonstd::rsplit_1(s, " ");
        REQUIRE(std::get<0>(t).empty());
        REQUIRE(std::get<1>(t).empty());
      }
    }
  }
}

TEST_CASE("envvars" * doctest::test_suite("nonstd"))
{
  {
    INFO("Expand environment variable");

    std::string test_value("test_value");
    ::setenv("TEST_ENV_VAR", test_value.c_str(), 1);

    REQUIRE("" == ccf::nonstd::expand_envvar(""));
    REQUIRE("not an env var" == ccf::nonstd::expand_envvar("not an env var"));
    REQUIRE(
      "$ENV_VAR_NOT_SET" == ccf::nonstd::expand_envvar("$ENV_VAR_NOT_SET"));
    REQUIRE(test_value == ccf::nonstd::expand_envvar("$TEST_ENV_VAR"));

    // ${} syntax is not supported
    REQUIRE(
      "${ENV_VAR_NOT_SET}" == ccf::nonstd::expand_envvar("${ENV_VAR_NOT_SET}"));
  }
  {
    INFO("Expand path");

    std::string test_value1("test_value1");
    ::setenv("TEST_ENV_VAR1", test_value1.c_str(), 1);
    std::string test_value2("test_value2");
    ::setenv("TEST_ENV_VAR2", test_value2.c_str(), 1);

    REQUIRE("" == ccf::nonstd::expand_envvars_in_path(""));
    REQUIRE("foo" == ccf::nonstd::expand_envvars_in_path("foo"));
    REQUIRE("foo/" == ccf::nonstd::expand_envvars_in_path("foo/"));
    REQUIRE("foo/bar" == ccf::nonstd::expand_envvars_in_path("foo/bar"));
    REQUIRE("/" == ccf::nonstd::expand_envvars_in_path("/"));
    REQUIRE("/foo" == ccf::nonstd::expand_envvars_in_path("/foo"));
    REQUIRE("/foo/" == ccf::nonstd::expand_envvars_in_path("/foo/"));
    REQUIRE("/foo/bar" == ccf::nonstd::expand_envvars_in_path("/foo/bar"));

    REQUIRE(
      fmt::format("{}", test_value1) ==
      ccf::nonstd::expand_envvars_in_path("$TEST_ENV_VAR1"));
    REQUIRE(
      fmt::format("{}/", test_value1) ==
      ccf::nonstd::expand_envvars_in_path("$TEST_ENV_VAR1/"));
    REQUIRE(
      fmt::format("{}/{}", test_value1, test_value2) ==
      ccf::nonstd::expand_envvars_in_path("$TEST_ENV_VAR1/$TEST_ENV_VAR2"));

    REQUIRE(
      fmt::format("/{}", test_value1) ==
      ccf::nonstd::expand_envvars_in_path("/$TEST_ENV_VAR1"));
    REQUIRE(
      fmt::format("/{}/", test_value1) ==
      ccf::nonstd::expand_envvars_in_path("/$TEST_ENV_VAR1/"));
    REQUIRE(
      fmt::format("/{}/{}", test_value1, test_value2) ==
      ccf::nonstd::expand_envvars_in_path("/$TEST_ENV_VAR1/$TEST_ENV_VAR2"));
  }
}

TEST_CASE("camel_case" * doctest::test_suite("nonstd"))
{
  {
    INFO("Default separator");
    REQUIRE(ccf::nonstd::camel_case("") == "");
    REQUIRE(ccf::nonstd::camel_case("abc") == "Abc");
    REQUIRE(ccf::nonstd::camel_case("abc", false) == "abc");

    REQUIRE(ccf::nonstd::camel_case("hello world") == "HelloWorld");
    REQUIRE(ccf::nonstd::camel_case("hello world", false) == "helloWorld");

    REQUIRE(
      ccf::nonstd::camel_case(
        "camel-with.many/many!many_many,many|many$separators") ==
      "CamelWithManyManyManyManyManyManySeparators");
    REQUIRE(
      ccf::nonstd::camel_case(
        "camel-with.many/many!many_many,many|many$separators", false) ==
      "camelWithManyManyManyManyManyManySeparators");

    REQUIRE(
      ccf::nonstd::camel_case("1handling2of3.numbers") ==
      "1handling2of3Numbers");
    REQUIRE(
      ccf::nonstd::camel_case("1handling2of3.numbers", false) ==
      "1handling2of3Numbers");

    REQUIRE(
      ccf::nonstd::camel_case(
        "camel_With-Existing_mixed-casing_Is-1Perhaps_2Surprising") ==
      "Camel_With-ExistingMixedCasing_Is-1Perhaps_2Surprising");
    REQUIRE(
      ccf::nonstd::camel_case(
        "camel_With-Existing_mixed-casing_Is-1Perhaps_2Surprising", false) ==
      "camel_With-ExistingMixedCasing_Is-1Perhaps_2Surprising");
  }
  {
    INFO("Custom separators");
    REQUIRE(ccf::nonstd::camel_case("hello world", true, "_") == "Hello world");
    REQUIRE(
      ccf::nonstd::camel_case("hello world", false, "_") == "hello world");

    REQUIRE(ccf::nonstd::camel_case("hello_world", true, "_") == "HelloWorld");
    REQUIRE(ccf::nonstd::camel_case("hello_world", false, "_") == "helloWorld");

    REQUIRE(
      ccf::nonstd::camel_case("what-about-/mixed/separators", true, "-") ==
      "WhatAbout-/mixed/separators");
    REQUIRE(
      ccf::nonstd::camel_case("what-about-/mixed/separators", false, "-") ==
      "whatAbout-/mixed/separators");

    REQUIRE(
      ccf::nonstd::camel_case("what-about-/mixed/separators", true, "/") ==
      "What-about-MixedSeparators");
    REQUIRE(
      ccf::nonstd::camel_case("what-about-/mixed/separators", false, "/") ==
      "what-about-MixedSeparators");
  }
}