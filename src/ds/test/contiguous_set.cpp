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

  T a, b, c;
  if constexpr (std::is_same_v<T, size_t>)
  {
    a = 0;
    b = 10;
    c = 20;
  }
  else if constexpr (std::is_same_v<T, int>)
  {
    a = -10;
    b = 0;
    c = 10;
  }

  REQUIRE_FALSE(cs.erase(a));
  REQUIRE_FALSE(cs.erase(b));
  REQUIRE_FALSE(cs.erase(c));

  REQUIRE(cs.size() == 0);
  REQUIRE(ccs.size() == 0);
  REQUIRE(cs.begin() == cs.end());
  REQUIRE(ccs.begin() == ccs.end());
  REQUIRE(cs.insert(b));
  // ccs.insert({}); // insert is non-const
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());

  // Insert again makes no change
  REQUIRE_FALSE(cs.insert(b));
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());

  {
    ds::ContiguousSet<T> cs2(ccs);
    REQUIRE(cs == cs2);

    REQUIRE(cs2.erase(b));
    REQUIRE(cs != cs2);

    REQUIRE(cs2.insert(b));
    REQUIRE(cs == cs2);
  }

  REQUIRE(cs.insert(a));
  REQUIRE(cs.size() == 2);
  REQUIRE(ccs.size() == 2);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() != cs.back());
  REQUIRE(ccs.front() != ccs.back());
  REQUIRE(cs.contains(b));
  REQUIRE(cs.contains(a));
  REQUIRE_FALSE(cs.contains(c));

  REQUIRE(cs.insert(c));
  REQUIRE(cs.size() == 3);
  REQUIRE(ccs.size() == 3);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() != cs.back());
  REQUIRE(ccs.front() != ccs.back());
  REQUIRE(cs.contains(b));
  REQUIRE(cs.contains(a));
  REQUIRE(cs.contains(c));

  REQUIRE(cs.erase(a));
  REQUIRE_FALSE(cs.erase(a));
  REQUIRE(cs.size() == 2);
  REQUIRE(ccs.size() == 2);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() != cs.back());
  REQUIRE(ccs.front() != ccs.back());
  REQUIRE(cs.contains(b));
  REQUIRE_FALSE(cs.contains(a));
  REQUIRE(cs.contains(c));

  REQUIRE(cs.erase(c));
  REQUIRE_FALSE(cs.erase(c));
  REQUIRE(cs.size() == 1);
  REQUIRE(ccs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  REQUIRE(ccs.begin() != ccs.end());
  REQUIRE(cs.front() == cs.back());
  REQUIRE(ccs.front() == ccs.back());
  REQUIRE(cs.contains(b));
  REQUIRE_FALSE(cs.contains(a));
  REQUIRE_FALSE(cs.contains(c));

  {
    auto it = cs.begin();
    REQUIRE(*it == b);
    ++it;
    REQUIRE(it == cs.end());
  }
  {
    auto it = cs.begin();
    REQUIRE(*it == b);
    it++;
    REQUIRE(it == cs.end());
  }

  {
    auto it = ccs.begin();
    REQUIRE(*it == b);
    ++it;
    REQUIRE(it == ccs.end());
  }
  {
    auto it = ccs.begin();
    REQUIRE(*it == b);
    it++;
    REQUIRE(it == ccs.end());
  }

  {
    size_t count = 0;
    for (auto n : cs)
    {
      REQUIRE(count++ == 0);
      REQUIRE(n == b);
    }
  }

  {
    size_t count = 0;
    for (auto n : ccs)
    {
      REQUIRE(count++ == 0);
      REQUIRE(n == b);
    }
  }

  REQUIRE(cs.erase(b));
  // ccs.erase(b); // erase is non-const
  REQUIRE(cs.size() == 0);
  REQUIRE(cs.begin() == cs.end());

  REQUIRE(cs.insert(b));
  REQUIRE(cs.size() == 1);
  REQUIRE(cs.begin() != cs.end());
  cs.clear();
  REQUIRE(cs.size() == 0);
  REQUIRE(cs.begin() == cs.end());
  REQUIRE_FALSE(cs.contains(b));
}

TEST_CASE("foo" * doctest::test_suite("contiguousset"))
{
  ds::ContiguousSet<size_t> cs;

  cs.insert(5);
  cs.insert(6);
  cs.insert(7);
  cs.insert(8);

  REQUIRE(cs.get_ranges().size() == 1);
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
  REQUIRE(cs.insert(10));
  REQUIRE(cs.insert(11));
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

TEST_CASE("Contiguous set extend" * doctest::test_suite("contiguousset"))
{
  ds::ContiguousSet<size_t> cs;

  // Distinct range at beginning
  cs.extend(5, 1);
  REQUIRE(cs.size() == 2);
  REQUIRE(cs.get_ranges().size() == 1);

  // Distinct range in middle
  cs.extend(10, 1);
  REQUIRE(cs.size() == 4);
  REQUIRE(cs.get_ranges().size() == 2);

  // Distinct range at end
  cs.extend(15, 1);
  REQUIRE(cs.size() == 6);
  REQUIRE(cs.get_ranges().size() == 3);

  SUBCASE("Distinct ranges")
  {
    cs.extend(1, 1);
    REQUIRE(cs.size() == 8);
    REQUIRE(cs.get_ranges().size() == 4);

    cs.extend(8, 0);
    REQUIRE(cs.size() == 9);
    REQUIRE(cs.get_ranges().size() == 5);

    cs.extend(13, 0);
    REQUIRE(cs.size() == 10);
    REQUIRE(cs.get_ranges().size() == 6);

    cs.extend(20, 1);
    REQUIRE(cs.size() == 12);
    REQUIRE(cs.get_ranges().size() == 7);
  }

  SUBCASE("Overlapping ranges")
  {
    cs.extend(3, 1);
    REQUIRE(cs.size() == 8);
    REQUIRE(cs.get_ranges().size() == 3);

    cs.extend(2, 4);
    REQUIRE(cs.size() == 9);
    REQUIRE(cs.get_ranges().size() == 3);

    cs.extend(7, 1);
    REQUIRE(cs.size() == 11);
    REQUIRE(cs.get_ranges().size() == 3);

    cs.extend(7, 2);
    REQUIRE(cs.size() == 12);
    REQUIRE(cs.get_ranges().size() == 2);

    cs.extend(7, 3);
    REQUIRE(cs.size() == 12);
    REQUIRE(cs.get_ranges().size() == 2);

    REQUIRE_FALSE(cs.contains(1));
    for (auto n = 2; n <= 11; ++n)
    {
      REQUIRE(cs.contains(n));
    }
    for (auto n = 12; n <= 14; ++n)
    {
      REQUIRE_FALSE(cs.contains(n));
    }
    REQUIRE(cs.contains(15));
    REQUIRE(cs.contains(16));
    REQUIRE_FALSE(cs.contains(17));

    cs.extend(9, 6);
    REQUIRE(cs.size() == 15);
    REQUIRE(cs.get_ranges().size() == 1);
  }

  SUBCASE("Overlapping and containing ranges")
  {
    cs.extend(9, 3);
    REQUIRE(cs.size() == 8);
    REQUIRE(cs.get_ranges().size() == 3);

    cs.extend(2, 11);
    REQUIRE(cs.size() == 14);
    REQUIRE(cs.get_ranges().size() == 2);

    cs.extend(1, 20);
    REQUIRE(cs.size() == 21);
    REQUIRE(cs.get_ranges().size() == 1);
  }
}
