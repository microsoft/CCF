// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/nonstd.h"

#include <algorithm>
#include <doctest/doctest.h>
#include <string>

TEST_CASE("split" * doctest::test_suite("nonstd"))
{
  {
    INFO("Basic splits");
    const auto s = "Good afternoon, good evening, and good night!";

    {
      INFO("Split by spaces");
      auto v = nonstd::split(s, " ");
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
      auto v = nonstd::split(s, ",");
      REQUIRE(v.size() == 3);
      REQUIRE(v[0] == "Good afternoon");
      REQUIRE(v[1] == " good evening");
      REQUIRE(v[2] == " and good night!");
    }

    {
      INFO("Split by comma-with-space");
      auto v = nonstd::split(s, ", ");
      REQUIRE(v.size() == 3);
      REQUIRE(v[0] == "Good afternoon");
      REQUIRE(v[1] == "good evening");
      REQUIRE(v[2] == "and good night!");
    }

    {
      INFO("Split by commas");
      auto v = nonstd::split(s, ",");
      REQUIRE(v.size() == 3);
      REQUIRE(v[0] == "Good afternoon");
      REQUIRE(v[1] == " good evening");
      REQUIRE(v[2] == " and good night!");
    }

    {
      INFO("Split by 'oo'");
      auto v = nonstd::split(s, "oo");
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
    const auto s = "  bob  ";

    {
      INFO("Split by spaces");
      auto v = nonstd::split(s, " ");
      REQUIRE(v.size() == 5);
      REQUIRE(v[0].empty());
      REQUIRE(v[1].empty());
      REQUIRE(v[2] == "bob");
      REQUIRE(v[3].empty());
      REQUIRE(v[4].empty());
    }
  }
}
