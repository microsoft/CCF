// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/unit_strings.h"

#include <cmath>
#include <doctest/doctest.h>

using namespace ccf::ds;

TEST_CASE("Size strings" * doctest::test_suite("unit strings"))
{
  REQUIRE_THROWS(convert_size_string(""));
  REQUIRE_THROWS(convert_size_string("12345INVALIDUNIT"));
  REQUIRE_THROWS(convert_size_string("12345ms"));

  REQUIRE(convert_size_string("0") == 0);
  REQUIRE(convert_size_string("12") == 12);
  REQUIRE(convert_size_string("12B") == 12);
  REQUIRE(convert_size_string("1001") == 1001);
  REQUIRE(convert_size_string("1001B") == 1001);
  REQUIRE(convert_size_string("3KB") == 3 * 1024);
  REQUIRE(convert_size_string("3 KB") == 3 * 1024);
  REQUIRE(convert_size_string("3kb") == 3 * 1024);
  REQUIRE(convert_size_string("3kB") == 3 * 1024);
  REQUIRE(convert_size_string("3Kb") == 3 * 1024);
  REQUIRE(convert_size_string("1024KB") == 1 * std::pow(1024, 2));
  REQUIRE(convert_size_string("3MB") == 3 * std::pow(1024, 2));
  REQUIRE(convert_size_string("3GB") == 3 * std::pow(1024, 3));
  REQUIRE(convert_size_string("3TB") == 3 * std::pow(1024, 4));
  REQUIRE(convert_size_string("3PB") == 3 * std::pow(1024, 5));
}

TEST_CASE("Time strings" * doctest::test_suite("unit strings"))
{
  REQUIRE_THROWS(convert_time_string(""));
  REQUIRE_THROWS(convert_time_string("12345INVALIDUNIT"));
  REQUIRE_THROWS(convert_time_string("12345KB"));

  REQUIRE(convert_time_string("0") == 0);
  REQUIRE(convert_time_string("12") == 12);
  REQUIRE(convert_time_string("12us") == 12);
  REQUIRE(convert_time_string("1001") == 1001);
  REQUIRE(convert_time_string("1001us") == 1001);
  REQUIRE(convert_time_string("3ms") == 3'000);
  REQUIRE(convert_time_string("3 ms") == 3'000);
  REQUIRE(convert_time_string("1234ms") == 1'234'000);
  REQUIRE(convert_time_string("3s") == 3'000'000);
  REQUIRE(convert_time_string("3min") == 60 * convert_time_string("3s"));
  REQUIRE(convert_time_string("3h") == 60 * convert_time_string("3min"));
}