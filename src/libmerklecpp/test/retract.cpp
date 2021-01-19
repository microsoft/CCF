// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "util.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <merklecpp.h>

#define PRINT_HASH_SIZE 3

int main()
{
  auto test_start_time = std::chrono::high_resolution_clock::now();
  double timeout = get_timeout();
  auto seed = std::time(0);
  std::cout << "seed=" << seed << " timeout=" << timeout << std::endl;

  try
  {
#ifndef NDEBUG
    const size_t num_trees = 128;
    const size_t max_num_leaves = 64 * 1024;
    const size_t max_retractions = 16;
#else
    const size_t num_trees = 256;
    const size_t max_num_leaves = 256 * 1024;
    const size_t max_retractions = 64;
#endif

    size_t total_leaves = 0, total_retractions = 0;

    for (size_t k = 0; k < num_trees && !timed_out(timeout, test_start_time);
         k++)
    {
      size_t num_leaves = 1 + (std::rand() / (double)RAND_MAX) * max_num_leaves;
      total_leaves += num_leaves;

      auto hashes = make_hashes(num_leaves);

      merkle::Tree mt;
      for (size_t i = 0; i < hashes.size(); i++)
      {
        mt.insert(hashes[i]);
        if (i > 0 && std::rand() / (double)RAND_MAX > 0.5)
        {
          mt.retract_to(mt.max_index() - 1);
          total_retractions++;
          mt.insert(hashes[i]);
          mt.retract_to(mt.max_index());
          if (mt.max_index() != i)
            std::runtime_error("invalid max index");
        }

        if ((std::rand() / (double)RAND_MAX) > 0.95)
        {
          mt.retract_to(random_index(mt));
          total_retractions++;
        }
      }

      for (size_t i = 0; i < max_retractions; i++)
      {
        mt.retract_to(random_index(mt));
        total_retractions++;
        if (mt.min_index() == mt.max_index())
          break;
      }

      if ((k && k % 1000 == 0) || k == num_trees - 1)
      {
        static char time_str[256] = "";
        std::time_t t = std::time(nullptr);
        std::strftime(time_str, sizeof(time_str), "%R", std::localtime(&t));
        std::cout << time_str << ": " << k << " trees, " << total_leaves
                  << " leaves, " << total_retractions << " retractions"
                  << ": OK." << std::endl;
      }
    }
  }
  catch (std::exception& ex)
  {
    std::cout << "Error: " << ex.what() << std::endl;
    return 1;
  }
  catch (...)
  {
    std::cout << "Error" << std::endl;
    return 1;
  }

  return 0;
}
