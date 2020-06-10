// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

crypto::Sha256Hash rand_hash()
{
  crypto::Sha256Hash hash;
  uint8_t* data = hash.h.data();
  for (size_t i = 0; i < hash.h.size(); ++i)
  {
    data[i] = rand();
  }
  return hash;
}

TEST_CASE("Building a tree")
{
  ccf::MerkleTreeHistory history;
  REQUIRE(history.get_first_index() == 0);
  REQUIRE(history.get_last_index() == 0);

  constexpr size_t hash_count = 10'000;
  for (size_t i = 1; i < hash_count; ++i)
  {
    auto h = rand_hash();
    history.append(h);
    REQUIRE(history.get_first_index() == 0);
    REQUIRE(history.get_last_index() == i);
  }

  constexpr size_t retract_point = hash_count / 3;
  history.retract(retract_point);
  REQUIRE(history.get_last_index() == retract_point);

  for (size_t i = retract_point + 1; i < hash_count; ++i)
  {
    auto h = rand_hash();
    history.append(h);
    REQUIRE(history.get_last_index() == i);
  }

  constexpr size_t flush_point = retract_point;
  const auto prev_first = history.get_first_index();
  history.flush(flush_point);
  const auto new_first = history.get_first_index();
  REQUIRE(new_first >= prev_first);
  REQUIRE(new_first <= flush_point);

  REQUIRE_THROWS(history.flush(new_first - 1));
  REQUIRE(history.get_first_index() == new_first);
}

TEST_CASE("First root")
{
  ccf::MerkleTreeHistory tree;
  const auto empty_root = tree.get_root();

  const auto h = rand_hash();
  {
    auto hash_copy = h;
    tree.append(hash_copy);
  }

  const auto single_root = tree.get_root();
  REQUIRE(empty_root != single_root);
  REQUIRE(single_root == h);
}

TEST_CASE("Index independence 1")
{
  ccf::MerkleTreeHistory tree1;
  for (size_t i = 0; i < 5; ++i)
  {
    auto h = rand_hash();
    tree1.append(h);
  }

  const auto root = tree1.get_root();
  ccf::MerkleTreeHistory tree2;
  tree2.append(root);

  for (size_t i = 0; i < 5; ++i)
  {
    const auto h = rand_hash();
    {
      auto h1 = h;
      tree1.append(h1);
    }
    {
      auto h2 = h;
      tree2.append(h2);
    }
  }

  REQUIRE(tree1.get_root() == tree2.get_root());
}

TEST_CASE("Index independence 2")
{
  std::map<uint64_t, crypto::Sha256Hash> hashes;
  for (uint64_t i = 0; i < 10; ++i)
  {
    hashes[i] = rand_hash();
  }

  std::vector<std::unique_ptr<ccf::MerkleTreeHistory>> trees;
  for (size_t i = 0; i < hashes.size(); ++i)
  {
    trees.emplace_back(std::make_unique<ccf::MerkleTreeHistory>());

    if (i > 0)
    {
      // Start later trees from the root of previous tree
      auto& tree = trees.back();
      auto& prev = trees[i - 1];
      auto root = prev->get_root();
      tree->append(root);
    }

    for (auto& tree : trees)
    {
      auto h = hashes[i];
      tree->append(h);
    }

    const auto first_root = trees[0]->get_root();
    for (auto& tree : trees)
    {
      REQUIRE(tree->get_root() == first_root);
    }
  }
}