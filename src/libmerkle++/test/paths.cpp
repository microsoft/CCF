#include <cassert>

#include <iostream>
#include <chrono>

#include <merkle++.h>

#include "util.h"

#define PRINT_HASH_SIZE 3

int main()
{
  try {
    const size_t num_trees = 256;

    for (size_t num_leaves = 1; num_leaves < num_trees; num_leaves++) {
      auto hashes = make_hashes(num_leaves);

      Merkle::Tree mt;
      for (auto h : hashes)
        mt.insert(h);
      Merkle::Tree::Hash root = mt.root();
      // std::cout << "R: " << root.to_string(PRINT_HASH_SIZE) << std::endl;
      // std::cout << mt.to_string(PRINT_HASH_SIZE) << std::endl;

      for (size_t i = 0; i < num_leaves; i++) {
        auto path = mt.path(i);
        assert(path->verify(root));
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
