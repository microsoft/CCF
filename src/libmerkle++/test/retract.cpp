#include <cstdlib>

#include <iostream>
#include <chrono>

#include <merkle++.h>

#include "util.h"

#define PRINT_HASH_SIZE 3

int main()
{
  try {
    #ifndef NDEBUG
    const size_t num_trees = 64;
    const size_t max_num_leaves = 64*1024;
    const size_t max_retractions = 16;
    #else
    const size_t num_trees = 256;
    const size_t max_num_leaves = 256*1024;
    const size_t max_retractions = 64;
    #endif

    // std::srand(0);
    std::srand(std::time(0));

    size_t total_paths = 0, total_leaves = 0, total_retractions = 0;

    for (size_t l=0; l < num_trees; l++) {
      size_t num_leaves = 1 + (std::rand()/(double)RAND_MAX) * max_num_leaves;
      total_leaves += num_leaves;

      auto hashes = make_hashes(num_leaves);

      Merkle::Tree mt;
      for (size_t i=0; i < hashes.size(); i++) {
        mt.insert(hashes[i]);
        if (i > 0 && std::rand()/(double)RAND_MAX > 0.5) {
          mt.retract_to(mt.max_index()-1);
          total_retractions++;
          mt.insert(hashes[i]);
          mt.retract_to(mt.max_index());
          if (mt.max_index() != i)
            std::runtime_error("invalid max index");
        }

        if (i % 997 == 0) {
          mt.retract_to(random_index(mt));
          total_retractions++;
        }
      }

      for (size_t i=0; i < max_retractions; i++) {
        mt.retract_to(random_index(mt));
        total_retractions++;
        if (mt.min_index() == mt.max_index())
          break;
      }
    }

    std::cout << num_trees << " trees, " << total_leaves << " leaves, " << total_retractions << " retractions: OK." << std::endl;
  }
  catch (std::exception &ex) {
    std::cout << "Error: " << ex.what() << std::endl;
    return 1;
  }
  catch (...) {
    std::cout << "Error" << std::endl;
    return 1;
  }

  return 0;
}
