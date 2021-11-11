// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "../contiguous_set.h"

#include <doctest/doctest.h>
#include <iostream>
#include <random>

template <typename T>
void test(T from, T to)
{
  // Include a random fraction of the range
  std::vector<T> sample;
  for (auto i = from; i < to; ++i)
  {
    if (rand() % 3 != 0)
    {
      sample.emplace_back(i);
    }
  }

  // Insert them in random order
  std::random_device rd;
  std::mt19937 g(rd());
  std::shuffle(sample.begin(), sample.end(), g);

  ds::ContiguousSet<T> cs;
  for (const auto& n : sample)
  {
    cs.insert(n);
  }

  // Confirm that all are present, and retrieved in-order
  REQUIRE(cs.size() == sample.size());
  REQUIRE(cs.get_ranges().size() <= cs.size());
  std::sort(sample.begin(), sample.end());
  auto sample_it = sample.begin();
  auto cs_it = cs.begin();
  while (sample_it != sample.end())
  {
    REQUIRE(*sample_it == *cs_it);
    ++sample_it;
    ++cs_it;
  }
  REQUIRE(cs_it == cs.end());
}

TEST_CASE_TEMPLATE(
  "Contiguous set API" * doctest::test_suite("contiguousset"), T, size_t, int)
{
  ds::ContiguousSet<T> cs;
  const auto& ccs = cs;

  T default_value = {};

  REQUIRE(cs.size() == 0);
  REQUIRE(ccs.size() == 0);
  REQUIRE(cs.begin() == cs.end());
  REQUIRE(ccs.begin() == ccs.end());
  cs.insert(default_value);
  // ccs.insert({}); // insert is non-const
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());

  // Insert again makes no change
  cs.insert(default_value);
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());

  {
    auto it = cs.begin();
    REQUIRE(*it == default_value);
    ++it;
    REQUIRE(it == cs.end());
  }
  {
    auto it = cs.begin();
    REQUIRE(*it == default_value);
    it++;
    REQUIRE(it == cs.end());
  }

  {
    auto it = ccs.begin();
    REQUIRE(*it == default_value);
    ++it;
    REQUIRE(it == ccs.end());
  }
  {
    auto it = ccs.begin();
    REQUIRE(*it == default_value);
    it++;
    REQUIRE(it == ccs.end());
  }

  {
    size_t count = 0;
    for (auto n : cs)
    {
      REQUIRE(count++ == 0);
      REQUIRE(n == default_value);
    }
  }

  {
    size_t count = 0;
    for (auto n : ccs)
    {
      REQUIRE(count++ == 0);
      REQUIRE(n == default_value);
    }
  }

  cs.erase(default_value);
  // ccs.erase(default_value); // erase is non-const
  REQUIRE(cs.size() == 0);
  REQUIRE(cs.begin() == cs.end());

  cs.insert(default_value);
  REQUIRE(cs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  cs.clear();
  REQUIRE(cs.size() == 0);
  REQUIRE(cs.begin() == cs.end());
}

TEST_CASE("Contiguous set explicit test" * doctest::test_suite("contiguousset"))
{
  ds::ContiguousSet<size_t> cs;

  cs.insert(10);
  cs.insert(8);
  cs.insert(12);
  REQUIRE(cs.size() == 3);
  REQUIRE(cs.get_ranges().size() == 3);

  cs.insert(11);
  REQUIRE(cs.size() == 4);
  REQUIRE(cs.get_ranges().size() == 2);

  cs.insert(9);
  REQUIRE(cs.size() == 5);
  REQUIRE(cs.get_ranges().size() == 1);

  REQUIRE(cs.erase(11));
  REQUIRE_FALSE(cs.erase(11));
  REQUIRE(cs.size() == 4);
  REQUIRE(cs.get_ranges().size() == 2);

  REQUIRE(cs.erase(10));
  REQUIRE_FALSE(cs.erase(10));
  REQUIRE(cs.size() == 3);
  REQUIRE(cs.get_ranges().size() == 2);

  REQUIRE(cs.erase(12));
  REQUIRE_FALSE(cs.erase(12));
  REQUIRE(cs.size() == 2);
  REQUIRE(cs.get_ranges().size() == 1);

  REQUIRE(cs.erase(8));
  REQUIRE_FALSE(cs.erase(8));
  REQUIRE(cs.size() == 1);
  REQUIRE(cs.get_ranges().size() == 1);

  cs.insert(5);
  cs.insert(8);
  cs.insert(11);
  cs.insert(10);
  REQUIRE(cs.size() == 5);
  REQUIRE(cs.get_ranges().size() == 2);

  cs.clear();
  REQUIRE(cs.size() == 0);
  REQUIRE(cs.get_ranges().size() == 0);
}

TEST_CASE("Contiguous set correctness" * doctest::test_suite("contiguousset"))
{
  for (auto i = 0; i < 10; ++i)
  {
    test<size_t>(0, 20);
    test<int>(0, 20);
    test<int>(-20, 20);
  }
}
