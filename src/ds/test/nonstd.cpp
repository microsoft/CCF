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

      {
        INFO("split(max_splits=3)");
        {
          auto v = nonstd::split(s, " ", 3);
          // NB: max_splits=3 => 4 returned segments
          REQUIRE(v.size() == 4);
          REQUIRE(v[0] == "Good");
          REQUIRE(v[1] == "afternoon,");
          REQUIRE(v[2] == "good");
          REQUIRE(v[3] == "evening, and good night!");
        }

        {
          auto v = nonstd::split(s, "afternoon", 3);
          // NB: max_splits=3, but only 1 split possible => 2 returned segments
          REQUIRE(v.size() == 2);
          REQUIRE(v[0] == "Good ");
          REQUIRE(v[1] == ", good evening, and good night!");
        }
      }

      {
        INFO("split_1");
        auto t = nonstd::split_1(s, ", ");
        REQUIRE(std::get<0>(t) == "Good afternoon");
        REQUIRE(std::get<1>(t) == "good evening, and good night!");
      }
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

    {
      const auto s = "  bob ";
      auto v = nonstd::split(s, " ");
      REQUIRE(v.size() == 4);
      REQUIRE(v[0].empty());
      REQUIRE(v[1].empty());
      REQUIRE(v[2] == "bob");
      REQUIRE(v[3].empty());
    }

    {
      const auto s = "bobbob";
      {
        auto v = nonstd::split(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0] == "bobbob");
      }

      {
        auto v = nonstd::split(s, "bob");
        REQUIRE(v.size() == 3);
        REQUIRE(v[0].empty());
        REQUIRE(v[1].empty());
        REQUIRE(v[2].empty());
      }

      {
        auto t = nonstd::split_1(s, "bob");
        REQUIRE(std::get<0>(t).empty());
        REQUIRE(std::get<1>(t) == "bob");
      }
    }

    {
      const auto s = "";
      {
        auto v = nonstd::split(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto v = nonstd::split(s, "bob");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto t = nonstd::split_1(s, " ");
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
      auto v = nonstd::rsplit(s, " ");
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
        auto v = nonstd::rsplit(s, " ", 3);
        // NB: max_splits=3 => 4 returned segments
        REQUIRE(v.size() == 4);
        REQUIRE(v[0] == "night!");
        REQUIRE(v[1] == "good");
        REQUIRE(v[2] == "and");
        REQUIRE(v[3] == "Good afternoon, good evening,");
      }

      {
        auto v = nonstd::rsplit(s, "afternoon", 3);
        // NB: max_splits=3, but only 1 split possible => 2 returned segments
        REQUIRE(v.size() == 2);
        REQUIRE(v[0] == ", good evening, and good night!");
        REQUIRE(v[1] == "Good ");
      }
    }

    {
      INFO("rsplit_1");
      auto t = nonstd::rsplit_1(s, ", ");
      REQUIRE(std::get<0>(t) == "Good afternoon, good evening");
      REQUIRE(std::get<1>(t) == "and good night!");
    }
  }

  {
    INFO("Edge cases");

    {
      const auto s = "  bob ";
      auto v = nonstd::rsplit(s, " ");
      REQUIRE(v.size() == 4);
      REQUIRE(v[0].empty());
      REQUIRE(v[1] == "bob");
      REQUIRE(v[2].empty());
      REQUIRE(v[3].empty());
    }

    {
      const auto s = "bobbob";
      {
        auto v = nonstd::rsplit(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0] == "bobbob");
      }

      {
        auto v = nonstd::rsplit(s, "bob");
        REQUIRE(v.size() == 3);
        REQUIRE(v[0].empty());
        REQUIRE(v[1].empty());
        REQUIRE(v[2].empty());
      }

      {
        auto t = nonstd::rsplit_1(s, "bob");
        REQUIRE(std::get<0>(t) == "bob");
        REQUIRE(std::get<1>(t).empty());
      }
    }

    {
      const auto s = "";
      {
        auto v = nonstd::rsplit(s, " ");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto v = nonstd::rsplit(s, "bob");
        REQUIRE(v.size() == 1);
        REQUIRE(v[0].empty());
      }

      {
        auto t = nonstd::rsplit_1(s, " ");
        REQUIRE(std::get<0>(t).empty());
        REQUIRE(std::get<1>(t).empty());
      }
    }
  }
}