#include <cassert>

#include <chrono>
#include <iostream>
#include <iomanip>

#include <MerkleTree.h>
#include <merkle++.h>

#include "util.h"

#define PRINT_HASH_SIZE 3

int main()
{
  try {
    Merkle::Tree mt;
    const size_t num_leaves = 11;
    auto hashes = make_hashes(num_leaves);

    for (size_t i = 0; i < hashes.size(); i++)
      mt.insert_lazy(hashes[i]);

    mt.rebuild();
    Merkle::Tree::Hash rebuilt_root = mt.root();
    std::cout << "scratch built: " << std::endl;
    std::cout << "R: " << rebuilt_root.to_string() << std::endl;
    std::cout << mt.to_string(PRINT_HASH_SIZE) << std::endl;


    merkle_tree *ec_mt = NULL;
    uint8_t *ec_hash = mt_init_hash(32);
    for (auto h : hashes) {
      if (!ec_mt) ec_mt = mt_create(h.bytes);
      else mt_insert(ec_mt, h.bytes);
    }
    mt_get_root(ec_mt, ec_hash);

    std::cout << "EverCrypt: " << std::endl;
    std::cout << "R: " << Merkle::Hash(ec_hash).to_string() << std::endl;
#ifdef HAVE_INSTRUMENTED_EVERCRYPT
    std::cout << "S: num_hash=" << mt_sha256_compress_calls << std::endl;
#endif

    mt_free_hash(ec_hash);
    mt_free(ec_mt);


    std::cout << std::endl << std::endl;

    Merkle::Tree mtt;
    for (auto h : hashes) {
      mtt.insert(h);
      // mtt.build_incremental();
    }
    // mtt.build_incremental();
    Merkle::Tree::Hash treelike_root = mtt.root();
    std::cout << "treelike: " << std::endl;
    std::cout << "R: " << treelike_root.to_string() << std::endl;
    std::cout << mtt.to_string(PRINT_HASH_SIZE) << std::endl;

    assert (rebuilt_root == treelike_root);


    for (size_t i = 0; i < num_leaves; i++) {
      auto path = mtt.path(i);
      std::cout << "P" << std::setw(2) << std::setfill('0') << i << ": " << path->to_string(PRINT_HASH_SIZE) << " " << std::endl;
      assert(path->verify(treelike_root));
    }
  }
  catch (...) {
    std::cout << "Error" << std::endl;
    return 1;
  }

  return 0;
}
