#include <iostream>
#include <chrono>

#include <MerkleTree.h>
#include <merkle++.h>

#include "util.h"

#define HSZ 32

void compare_roots(Merkle::Tree &mt, merkle_tree *ec_mt) {
  auto root = mt.root();

  uint8_t *ec_root_bytes = mt_init_hash(HSZ);
  mt_get_root(ec_mt, ec_root_bytes);
  auto ec_root = Merkle::Hash(ec_root_bytes);
  mt_free_hash(ec_root_bytes);

  if (root != ec_root) {
    std::cout << mt.num_leaves() << ": " << root.to_string() << " != " << ec_root.to_string() << std::endl;
    std::cout << mt.to_string(3) << std::endl;
    throw std::runtime_error("root hash mismatch");
  }
}

int main()
{
  merkle_tree *ec_mt = NULL;
  uint8_t *ec_hash = mt_init_hash(HSZ);

  try {
    #ifndef NDEBUG
    const size_t num_trees = 1024;
    const size_t root_interval = 256;
    #else
    const size_t num_trees = 4096;
    const size_t root_interval = 128;
    #endif

    for (size_t k = 0; k < num_trees; k++) {
      Merkle::Tree mt;

      // Build trees with k+1 leaves
      int j = 0;
      std::vector<Merkle::Hash> hashes = make_hashes(k+1);
      for (const auto h : hashes) {
        mt.insert(h);

        memcpy(ec_hash, h.bytes, HSZ);
        if (!ec_mt) ec_mt = mt_create(ec_hash);
        else mt_insert(ec_mt, ec_hash);

        if ((j++ % root_interval) == 0)
          compare_roots(mt, ec_mt);
      }

      compare_roots(mt, ec_mt);

      mt_free(ec_mt);
      ec_mt = NULL;
    }

  }
  catch (std::exception &ex) {
    std::cout << "Error: " << ex.what() << std::endl;
    mt_free_hash(ec_hash);
    mt_free(ec_mt);
    return 1;
  }
  catch (...) {
    std::cout << "Error" << std::endl;
    mt_free_hash(ec_hash);
    mt_free(ec_mt);
    return 1;
  }

  mt_free_hash(ec_hash);

  return 0;
}