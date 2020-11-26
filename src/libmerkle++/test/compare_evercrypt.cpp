#include <cassert>

#include <iostream>
#include <chrono>

#include <MerkleTree.h>
#include <merkle++.h>

#include "util.h"

#define HSZ 32

int main()
{
  try {
    #ifndef NDEBUG
    const size_t num_comp = 1024;
    #else
    const size_t num_comp = 4096;
    #endif

    for (size_t k = 0; k < num_comp; k++) {
      Merkle::Tree mt;
      merkle_tree *ec_mt = NULL;

      // Build trees of size k+1
      std::vector<Merkle::Hash> hashes = make_hashes(k+1);
      for (const auto h : hashes) {
        mt.insert(h);

        uint8_t *ec_hash = mt_init_hash(HSZ);
        memcpy(ec_hash, h.bytes, HSZ);
        if (!ec_mt) ec_mt = mt_create(ec_hash);
        else mt_insert(ec_mt, ec_hash);
        mt_free_hash(ec_hash);
      }

      // Compare roots
      uint8_t *ec_root_bytes = mt_init_hash(HSZ);
      mt_get_root(ec_mt, ec_root_bytes);

      auto root = mt.root();
      auto ec_root = Merkle::Hash(ec_root_bytes);

      if (root != ec_root) {
        std::cout << k << ": " << root.to_string() << " != " << ec_root.to_string() << std::endl;
        return 1;
      }

      mt_free_hash(ec_root_bytes);
      mt_free(ec_mt);
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