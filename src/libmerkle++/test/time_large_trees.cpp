#include <cassert>

#include <iostream>
#include <chrono>

#include <MerkleTree.h>
#include <merkle++.h>

#include "util.h"

#define HSZ 32

int main() {
  try {
    #ifndef NDEBUG
    const size_t num_leaves = 16*1024;
    const size_t root_interval = 128;
    #else
    const size_t num_leaves = 4*1024*1024;
    const size_t root_interval = 1024;
    #endif

    auto hashes = make_hashes(num_leaves);

    Merkle::Tree mt;
    size_t j = 0;
    auto start = std::chrono::high_resolution_clock::now();
    for (auto h : hashes) {
      mt.insert(h);
      if ((j++ % root_interval) == 0)
        mt.root();
    }
    // auto root = mt.root();
    auto stop = std::chrono::high_resolution_clock::now();
    double seconds = std::chrono::duration_cast<std::chrono::nanoseconds>(stop-start).count()/1e9;
    std::cout << "NEW:"
      << mt.statistics.to_string()
      << " in " << seconds << " sec" << std::endl;

    std::vector<uint8_t*> ec_hashes;
    for (auto h : hashes) {
      ec_hashes.push_back(mt_init_hash(HSZ));
      memcpy(ec_hashes.back(), h.bytes, HSZ);
    }

    uint8_t *ec_root = mt_init_hash(HSZ);
    size_t num_ec_roots = 1;
    start = std::chrono::high_resolution_clock::now();
    merkle_tree *ec_mt = mt_create(ec_hashes[0]);
    mt_get_root(ec_mt, ec_root);
    for (size_t i=1; i < ec_hashes.size(); i++) {
      mt_insert(ec_mt, ec_hashes[i]);
      if (i % root_interval == 0) {
        mt_get_root(ec_mt, ec_root);
        num_ec_roots++;
      }
    }
    stop = std::chrono::high_resolution_clock::now();
    seconds = std::chrono::duration_cast<std::chrono::nanoseconds>(stop-start).count()/1e9;
    std::cout << "EC :"
      << " num_insert=" << ec_hashes.size()
#ifdef HAVE_INSTRUMENTED_EVERCRYPT
      << " num_hash=" << mt_sha256_compress_calls
#endif
      << " num_root=" << num_ec_roots
      << " in " << seconds << " sec" << std::endl;

    for (auto h : ec_hashes)
      mt_free_hash(h);
    mt_free_hash(ec_root);
    mt_free(ec_mt);
  }
  catch (...) {
    std::cout << "Error" << std::endl;
    return 1;
  }

  return 0;
}