// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/cli_helper.h"
#include "ds/logger.h"
#include "ds/nonstd.h"

#include <cmath>
#include <doctest/doctest.h>

TEST_CASE("Size strings" * doctest::test_suite("cli"))
{
  std::vector<std::pair<std::string, size_t>> test_vectors = {
    {"", 0}, {"B", 0}, {"KB", 1}, {"MB", 2}, {"GB", 3}, {"TB", 4}};

  std::vector<size_t> size_digits = {
    0, 1, 10, 55, 100, 101, 1000, 1024, 100'000, 2'000'000};

  for (auto const& size_digit : size_digits)
  {
    for (auto const& test_vector : test_vectors)
    {
      auto size_string = fmt::format("{}{}", size_digit, test_vector.first);
      REQUIRE(
        cli::convert_size_string(size_string) ==
        size_digit * std::pow(1024, test_vector.second));

      // Lower case
      nonstd::to_lower(size_string);
      REQUIRE(
        cli::convert_size_string(size_string) ==
        size_digit * std::pow(1024, test_vector.second));
    }
  }
}

TEST_CASE("Time strings" * doctest::test_suite("cli"))
{
  std::vector<std::pair<std::string, std::pair<double, size_t>>> test_vectors =
    {{"", {1, 0}},
     {"us", {1, 0}},
     {"ms", {1, 3}},
     {"s", {1, 6}},
     {"min", {60, 6}},
     {"h", {3.6, 9}}};

  std::vector<size_t> time_digits = {
    0, 1, 10, 55, 100, 101, 1000, 1024, 100'000, 2'000'000};

  for (auto const& time_digit : time_digits)
  {
    for (auto const& test_vector : test_vectors)
    {
      auto const& factors = test_vector.second;
      auto time_string = fmt::format("{}{}", time_digit, test_vector.first);
      REQUIRE(
        cli::convert_time_string(time_string) ==
        time_digit * factors.first * std::pow(10, factors.second));
    }
  }
}