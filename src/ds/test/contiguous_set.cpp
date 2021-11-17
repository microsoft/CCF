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
    REQUIRE(cs.insert(n));
  }

  // Confirm that all are present, and retrieved in-order
  REQUIRE(cs.size() == sample.size());
  REQUIRE(cs.get_ranges().size() <= cs.size());
  std::sort(sample.begin(), sample.end());
  auto sample_it = sample.begin();
  auto cs_it = cs.begin();
  for (T n = from; n <= to; ++n)
  {
    if (sample_it != sample.end() && *sample_it == n)
    {
      REQUIRE(cs.contains(n));
      REQUIRE(cs.find(n) != cs.end());
      REQUIRE(n == *cs_it);
      ++sample_it;
      ++cs_it;
    }
    else
    {
      REQUIRE_FALSE(cs.contains(n));
      REQUIRE(cs.find(n) == cs.end());
    }
  }
  REQUIRE(cs_it == cs.end());
}

TEST_CASE_TEMPLATE(
  "Contiguous set API" * doctest::test_suite("contiguousset"), T, size_t, int)
{
  ds::ContiguousSet<T> cs;
  const auto& ccs = cs;

  T min_value = std::numeric_limits<T>::min();
  T max_value = std::numeric_limits<T>::max();
  T default_value = (min_value / 2) + (max_value / 2);

  REQUIRE(cs.size() == 0);
  REQUIRE(ccs.size() == 0);
  REQUIRE(cs.begin() == cs.end());
  REQUIRE(ccs.begin() == ccs.end());
  REQUIRE(cs.insert(default_value));
  // ccs.insert({}); // insert is non-const
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());

  // Insert again makes no change
  REQUIRE_FALSE(cs.insert(default_value));
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());

  {
    ds::ContiguousSet<T> cs2(ccs);
    REQUIRE(cs == cs2);

    REQUIRE(cs2.erase(default_value));
    REQUIRE(cs != cs2);

    REQUIRE(cs2.insert(default_value));
    REQUIRE(cs == cs2);
  }

  REQUIRE(cs.insert(min_value));
  REQUIRE(cs.size() == 2);
  REQUIRE(ccs.size() == 2);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() != cs.back());
  REQUIRE(ccs.front() != ccs.back());
  REQUIRE(cs.contains(default_value));
  REQUIRE(cs.contains(min_value));
  REQUIRE_FALSE(cs.contains(max_value));

  REQUIRE(cs.insert(max_value));
  REQUIRE(cs.size() == 3);
  REQUIRE(ccs.size() == 3);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() != cs.back());
  REQUIRE(ccs.front() != ccs.back());
  REQUIRE(cs.contains(default_value));
  REQUIRE(cs.contains(min_value));
  REQUIRE(cs.contains(max_value));

  REQUIRE(cs.erase(min_value));
  REQUIRE_FALSE(cs.erase(min_value));
  REQUIRE(cs.size() == 2);
  REQUIRE(ccs.size() == 2);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() != cs.back());
  REQUIRE(ccs.front() != ccs.back());
  REQUIRE(cs.contains(default_value));
  REQUIRE_FALSE(cs.contains(min_value));
  REQUIRE(cs.contains(max_value));

  REQUIRE(cs.erase(max_value));
  REQUIRE_FALSE(cs.erase(max_value));
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());
  REQUIRE(cs.contains(default_value));
  REQUIRE_FALSE(cs.contains(min_value));
  REQUIRE_FALSE(cs.contains(max_value));

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

  REQUIRE(cs.erase(default_value));
  // ccs.erase(default_value); // erase is non-const
  REQUIRE(cs.size() == 0);
  REQUIRE(cs.begin() == cs.end());

  REQUIRE(cs.insert(default_value));
  REQUIRE(cs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  cs.clear();
  REQUIRE(cs.size() == 0);
  REQUIRE(cs.begin() == cs.end());
  REQUIRE_FALSE(cs.contains(default_value));
}

TEST_CASE("Contiguous set explicit test" * doctest::test_suite("contiguousset"))
{
  ds::ContiguousSet<size_t> cs;

  REQUIRE(cs.insert(10));
  REQUIRE(cs.insert(8));
  REQUIRE(cs.insert(12));
  REQUIRE(cs.size() == 3);
  REQUIRE(cs.get_ranges().size() == 3);

  REQUIRE(cs.find(10) != cs.end());
  REQUIRE(cs.find(10).it->first == 10);
  REQUIRE(cs.find(10).offset == 0);
  REQUIRE(cs.find(9) == cs.end());

  REQUIRE(cs.insert(11));
  REQUIRE(cs.size() == 4);
  REQUIRE(cs.get_ranges().size() == 2);

  REQUIRE(cs.find(10) != cs.end());
  REQUIRE(cs.find(10).it->first == 10);
  REQUIRE(cs.find(10).offset == 0);
  REQUIRE(cs.find(9) == cs.end());

  REQUIRE(cs.insert(9));
  REQUIRE(cs.size() == 5);
  REQUIRE(cs.get_ranges().size() == 1);

  REQUIRE(cs.find(10) != cs.end());
  REQUIRE(cs.find(10).it->first == 8);
  REQUIRE(cs.find(10).offset == 2);
  REQUIRE(cs.find(9) != cs.end());
  REQUIRE(cs.find(9).it->first == 8);
  REQUIRE(cs.find(9).offset == 1);

  REQUIRE(cs.erase(11));
  REQUIRE_FALSE(cs.erase(11));
  REQUIRE(cs.size() == 4);
  REQUIRE(cs.get_ranges().size() == 2);
  REQUIRE(cs.find(10) != cs.end());

  REQUIRE(cs.erase(10));
  REQUIRE_FALSE(cs.erase(10));
  REQUIRE(cs.size() == 3);
  REQUIRE(cs.get_ranges().size() == 2);
  REQUIRE(cs.find(10) == cs.end());

  REQUIRE(cs.erase(12));
  REQUIRE_FALSE(cs.erase(12));
  REQUIRE(cs.size() == 2);
  REQUIRE(cs.get_ranges().size() == 1);

  REQUIRE(cs.erase(8));
  REQUIRE_FALSE(cs.erase(8));
  REQUIRE(cs.size() == 1);
  REQUIRE(cs.get_ranges().size() == 1);

  REQUIRE(cs.insert(5));
  REQUIRE(cs.insert(8));
  REQUIRE(cs.insert(11));
  REQUIRE(cs.insert(10));
  REQUIRE(cs.size() == 5);
  REQUIRE(cs.get_ranges().size() == 2);

  REQUIRE(cs.find(5) != cs.end());
  REQUIRE(cs.find(5).it->first == 5);
  REQUIRE(cs.find(5).offset == 0);
  REQUIRE(cs.find(9) != cs.end());
  REQUIRE(cs.find(9).it->first == 8);
  REQUIRE(cs.find(9).offset == 1);

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
