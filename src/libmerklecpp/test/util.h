// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <chrono>
#include <iostream>
#include <merklecpp.h>
#include <vector>

inline std::vector<merkle::Hash> make_hashes(size_t n, size_t print_size = 3)
{
  std::vector<merkle::Hash> hashes;
  merkle::Tree::Hash h;
  for (size_t i = 0; i < n; i++)
  {
    hashes.push_back(h);
    for (size_t j = print_size - 1; ++h.bytes[j] == 0 && j != -1; j--)
      ;
  }
  return hashes;
}

inline size_t random_index(merkle::Tree& mt)
{
  return mt.min_index() +
    (std::rand() / (double)RAND_MAX) * (mt.max_index() - mt.min_index());
}

inline double get_timeout()
{
  double r = 240.0;
  auto to = getenv("CTEST_TIMEOUT");
  if (to)
  {
    std::cout << "timeout string: " << to << std::endl;
    r = atof(to);
  }
  std::cout << "test timeout: " << r << " sec" << std::endl;
  return r;
}

inline bool timed_out(
  double timeout,
  const std::chrono::high_resolution_clock::time_point& test_start_time)
{
  auto now = std::chrono::high_resolution_clock::now();
  double seconds =
    std::chrono::duration_cast<std::chrono::nanoseconds>(now - test_start_time)
      .count() /
    1e9;
  return seconds > 0.90 * timeout;
}