// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "util.h"

#include <MerkleTree.h>
#include <chrono>
#include <iostream>
#include <merklecpp.h>

#define HSZ 32
#define PRNTSZ 3

void dump_ec_tree(merkle_tree* mt)
{
  std::cout << "hs=" << std::endl;
  for (size_t i = 0; i < mt->hs.sz; i++)
  {
    MerkleTree_Low_Datastructures_hash_vec hv = mt->hs.vs[i];
    if (hv.sz > 0)
    {
      std::cout << i << ":";
      for (size_t j = 0; j < hv.sz; j++)
      {
        std::cout << " " << merkle::Hash(hv.vs[j]).to_string(PRNTSZ);
      }
      std::cout << std::endl;
    }
  }
  std::cout << "root=" << merkle::Hash(mt->mroot).to_string(PRNTSZ)
            << std::endl;
  std::cout << "rhs=";
  for (size_t i = 0; i < mt->rhs.sz; i++)
    std::cout << " " << merkle::Hash(mt->rhs.vs[i]).to_string(PRNTSZ);
  std::cout << std::endl;
  std::cout << "rhs_ok=" << mt->rhs_ok << std::endl;
  std::cout << "i=" << mt->i << ", j=" << mt->j << std::endl;
}

void compare_roots(merkle::Tree& mt, merkle_tree* ec_mt)
{
  auto root = mt.root();

  uint8_t* ec_root_bytes = mt_init_hash(HSZ);
  mt_get_root(ec_mt, ec_root_bytes);
  auto ec_root = merkle::Hash(ec_root_bytes);
  mt_free_hash(ec_root_bytes);

  if (root != ec_root)
  {
    std::cout << mt.num_leaves() << ": " << root.to_string()
              << " != " << ec_root.to_string() << std::endl;
    std::cout << mt.to_string(PRNTSZ) << std::endl;
    std::cout << "EverCrypt tree: " << std::endl;
    dump_ec_tree(ec_mt);
    throw std::runtime_error("root hash mismatch");
  }
}

int main()
{
  merkle_tree* ec_mt = NULL;
  uint8_t* ec_hash = mt_init_hash(HSZ);

  try
  {
#ifndef NDEBUG
    const size_t num_trees = 1024;
    const size_t root_interval = 31;
#else
    const size_t num_trees = 4096;
    const size_t root_interval = 128;
#endif

    // std::srand(0);
    std::srand(std::time(0));

    size_t total_inserts = 0, total_flushes = 0, total_retractions = 0;

    for (size_t k = 0; k < num_trees; k++)
    {
      merkle::Tree mt;

      // Build trees with k+1 leaves
      int j = 0;
      std::vector<merkle::Hash> hashes = make_hashes(k + 1);
      for (const auto h : hashes)
      {
        mt.insert(h);
        total_inserts++;

        memcpy(ec_hash, h.bytes, HSZ);
        if (!ec_mt)
          ec_mt = mt_create(ec_hash);
        else
          mt_insert(ec_mt, ec_hash);

        if ((j++ % root_interval) == 0)
        {
          size_t index =
            mt.min_index() + ((mt.max_index() - mt.min_index()) / 3);
          mt.flush_to(index);
          if (!mt_flush_to_pre(ec_mt, index))
            throw std::runtime_error("EverCrypt flush precondition violation");
          mt_flush_to(ec_mt, index);
          total_flushes++;
          compare_roots(mt, ec_mt);
        }

        if ((std::rand() / (double)RAND_MAX) > 0.9)
        {
          size_t index = random_index(mt);
          mt.retract_to(index);
          if (!mt_retract_to_pre(ec_mt, index))
            throw std::runtime_error(
              "EverCrypt retract precondition violation");
          mt_retract_to(ec_mt, index);
          total_retractions++;
          compare_roots(mt, ec_mt);
        }

        if (
          (total_inserts % 1000000 == 0) ||
          (k == num_trees - 1 && h == hashes.back()))
        {
          static char time_str[256] = "";
          std::time_t t = std::time(nullptr);
          std::strftime(time_str, sizeof(time_str), "%R", std::localtime(&t));
          std::cout << time_str << ": " << k << " trees, " << total_inserts
                    << " inserts, " << total_flushes << " flushes, "
                    << total_retractions << " retractions: OK" << std::endl;
        }
      }

      compare_roots(mt, ec_mt);

      mt_free(ec_mt);
      ec_mt = NULL;
    }
  }
  catch (std::exception& ex)
  {
    std::cout << "Error: " << ex.what() << std::endl;
    mt_free_hash(ec_hash);
    mt_free(ec_mt);
    return 1;
  }
  catch (...)
  {
    std::cout << "Error" << std::endl;
    mt_free_hash(ec_hash);
    mt_free(ec_mt);
    return 1;
  }

  mt_free_hash(ec_hash);

  return 0;
}