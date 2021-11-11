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

    std::cout << "Inserted " << n << std::endl;
    for (auto it = cs.begin(); it != cs.end(); ++it)
    {
      std::cout << "  " << *it;
    }
    std::cout << std::endl;
  }
  std::cout << "Done inserting" << std::endl;

  // Confirm that all are present, and retrieved in-order
  REQUIRE(cs.size() == sample.size());
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

TEST_CASE("Contiguous set API" * doctest::test_suite("contiguousset"))
{
  // TODO: Confirm all expected types/methods are present, can be called,
  // compile
}

TEST_CASE("Contiguous set correctness" * doctest::test_suite("contiguousset"))
{
  // test<size_t>(0, 20);
  // test<int>(0, 20);
  test<int>(-20, 20);
}
