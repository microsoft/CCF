// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <chrono>
#include <iomanip>
#include <iostream>

#ifdef HAVE_EVERCRYPT
#  include <MerkleTree.h>
#endif

#include "util.h"

#include <merklecpp.h>

#define PRINT_HASH_SIZE 3

int main()
{
  try
  {
    const size_t num_leaves = 11;
    {
      auto hashes = make_hashes(num_leaves);

      merkle::Tree mt;
      for (auto h : hashes)
        mt.insert(h);
      merkle::Tree::Hash root = mt.root();
      std::cout << mt.to_string(PRINT_HASH_SIZE) << std::endl;

#ifdef HAVE_EVERCRYPT
      merkle_tree* ec_mt = NULL;
      uint8_t* ec_hash = mt_init_hash(32);
      for (auto h : hashes)
      {
        if (!ec_mt)
          ec_mt = mt_create(h.bytes);
        else
          mt_insert(ec_mt, h.bytes);
      }
      mt_get_root(ec_mt, ec_hash);

      std::cout << "EverCrypt: " << std::endl;
      std::cout << "R: " << merkle::Hash(ec_hash).to_string() << std::endl;

      mt_free_hash(ec_hash);
      mt_free(ec_mt);
      std::cout << std::endl;
#endif

      std::cout << "Paths: " << std::endl;
      for (size_t i = mt.min_index(); i <= mt.max_index(); i++)
      {
        mt.flush_to(i);
        auto path = mt.path(i);
        std::cout << "P" << std::setw(2) << std::setfill('0') << i << ": "
                  << path->to_string(PRINT_HASH_SIZE) << " " << std::endl;
        if (!path->verify(root))
          throw std::runtime_error("root hash mismatch");
        std::vector<uint8_t> chk = *path;
      }

      std::vector<uint8_t> buffer;
      mt.serialise(buffer);
      merkle::Tree dmt(buffer);
      if (mt.root() != dmt.root())
        throw std::runtime_error("root hash mismatch");

      std::cout << std::endl;
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
