#include <cstdlib>

#include <iostream>
#include <chrono>
#include <map>
#include <stdexcept>

#include <merkle++.h>

#include "util.h"

#define PRINT_HASH_SIZE 3

int main()
{
  try {
    #ifndef NDEBUG
    const size_t num_trees = 64;
    const size_t max_num_leaves = 8*1024;
    #else
    const size_t num_trees = 256;
    const size_t max_num_leaves = 64*1024;
    #endif

    // std::srand(0);
    std::srand(std::time(0));

    size_t total_paths = 0, total_leaves = 0, total_roots = 0;

    for (size_t k=0; k < num_trees; k++) {
      std::map<size_t, Merkle::Hash> past_roots;
      size_t num_leaves = 1 + (std::rand()/(double)RAND_MAX) * max_num_leaves;
      total_leaves += num_leaves;
      auto hashes = make_hashes(num_leaves);

      {
        // Extract some normal roots along the way
        Merkle::Tree mt;
        for (size_t i=0; i < hashes.size(); i++) {
          mt.insert(hashes[i]);
          if ((std::rand()/(double)RAND_MAX) > 0.95)
            past_roots[i] = mt.root();
        }
      }

      // Build new tree without taking roots
      Merkle::Tree mt;
      for (auto &h : hashes)
        mt.insert(h);

      // Extract and check past roots
      for (auto &kv : past_roots) {
        auto pr = mt.past_root(kv.first);
        total_roots++;
        if (*pr != kv.second) {
          std::cout << pr->to_string(PRINT_HASH_SIZE) << " != "
                    << kv.second.to_string(PRINT_HASH_SIZE) << std::endl;
          throw std::runtime_error("past root hash mismatch");
        }
      }

      if ((k && k % 1000 == 999) || k == num_trees-1) {
        static char time_str[256] = "";
        std::time_t t = std::time(nullptr);
        std::strftime(time_str, sizeof(time_str), "%R", std::localtime(&t));
        std::cout << time_str << ": "
                  << k+1 << " trees, "
                  << total_leaves << " leaves, "
                  << total_roots << " roots"
                  << ": OK."
                  << std::endl;
      }
    }
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
