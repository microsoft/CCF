// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "util.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <merklecpp.h>
#include <stdexcept>

#define PRINT_HASH_SIZE 3

int main()
{
  try
  {
#ifndef NDEBUG
    const size_t num_trees = 32;
    const size_t max_num_leaves = 32 * 1024;
#else
    const size_t num_trees = 256;
    const size_t max_num_leaves = 128 * 1024;
#endif

    // std::srand(0);
    std::srand(std::time(0));

    size_t total_leaves = 0, total_flushes = 0, total_retractions = 0;

    for (size_t k = 0; k < num_trees; k++)
    {
      std::map<size_t, merkle::Hash> past_roots;
      size_t num_leaves = 1 + (std::rand() / (double)RAND_MAX) * max_num_leaves;
      total_leaves += num_leaves;
      auto hashes = make_hashes(num_leaves);

      // Build
      merkle::Tree mt;
      for (auto& h : hashes)
      {
        assert(mt.invariant());
        mt.insert(h);
        assert(mt.invariant());
        if ((std::rand() / (double)RAND_MAX) > 0.95)
        {
          assert(mt.invariant());
          mt.flush_to(random_index(mt));
          assert(mt.invariant());
          total_flushes++;
        }
        if ((std::rand() / (double)RAND_MAX) > 0.95)
        {
          assert(mt.invariant());
          mt.retract_to(random_index(mt));
          assert(mt.invariant());
          total_retractions++;
        }
      }

      // Serialise
      std::vector<uint8_t> buffer;
      mt.serialise(buffer);

      // Deserialise
      size_t index = 0;
      merkle::Tree mt2(buffer, index);

      // Check roots and other properties
      if (
        mt.root() != mt2.root() || mt.min_index() != mt2.min_index() ||
        mt.max_index() != mt2.max_index() ||
        mt.num_leaves() != mt2.num_leaves() ||
        mt.serialised_size() != mt2.serialised_size() ||
        mt.size() != mt2.size())
      {
        std::cout << "before:" << std::endl
                  << mt.to_string(PRINT_HASH_SIZE) << std::endl;
        std::cout << "after:" << std::endl
                  << mt2.to_string(PRINT_HASH_SIZE) << std::endl;
        throw std::runtime_error("tree properties mismatch");
      }

      if ((k && k % 1000 == 999) || k == num_trees - 1)
      {
        static char time_str[256] = "";
        std::time_t t = std::time(nullptr);
        std::strftime(time_str, sizeof(time_str), "%R", std::localtime(&t));
        std::cout << time_str << ": " << k + 1 << " trees, " << total_leaves
                  << " leaves, " << total_flushes << " flushes, "
                  << total_retractions << " retractions"
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
