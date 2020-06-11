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
  REQUIRE(history.begin_index() == 0);
  REQUIRE(history.end_index() == 0);

  constexpr size_t hash_count = 10'000;
  for (size_t i = 1; i < hash_count; ++i)
  {
    auto h = rand_hash();
    history.append(h);
    REQUIRE(history.begin_index() == 0);
    REQUIRE(history.end_index() == i);
  }

  constexpr size_t retract_point = hash_count / 3;
  history.retract(retract_point);
  REQUIRE(history.end_index() == retract_point);

  for (size_t i = retract_point + 1; i < hash_count; ++i)
  {
    auto h = rand_hash();
    history.append(h);
    REQUIRE(history.end_index() == i);
  }

  constexpr size_t flush_point = retract_point;
  const auto prev_first = history.begin_index();
  history.flush(flush_point);
  const auto new_first = history.begin_index();
  REQUIRE(new_first >= prev_first);
  REQUIRE(new_first <= flush_point);

  REQUIRE_THROWS(history.flush(new_first - 1));
  REQUIRE(history.begin_index() == new_first);
}

TEST_CASE("Tree equality")
{
  ccf::MerkleTreeHistory tree1;
  ccf::MerkleTreeHistory tree2;
  REQUIRE(tree1.get_root() == tree2.get_root());

  for (size_t i = 0; i < 100; ++i)
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
    REQUIRE(tree1.get_root() == tree2.get_root());
  }

  {
    INFO("Flushing doesn't affect root");
    const auto final_root = tree1.get_root();
    for (size_t i = 0; i < tree1.end_index(); ++i)
    {
      tree1.flush(i + 1);
      REQUIRE(tree1.get_root() == final_root);
    }
  }
}

TEST_CASE("Retrieving hashes")
{
  constexpr size_t hash_count = 1'000;

  std::map<uint64_t, crypto::Sha256Hash> hashes;
  hashes[0] = crypto::Sha256Hash(); // Default index 0 always contains all-0s

  ccf::MerkleTreeHistory history;

  size_t index = 1;
  while (hashes.size() < hash_count)
  {
    auto h = rand_hash();
    hashes[index++] = h;
    history.append(h);
  }

  for (const auto& [i, hash] : hashes)
  {
    const auto h = history.get_hash(i);
    REQUIRE(h == hash);
  }

  for (const auto& [i, hash] : hashes)
  {
    history.flush(i);
    const auto h = history.get_hash(i);
    REQUIRE(h == hash);
  }
}

TEST_CASE("Deserialised")
{
  constexpr size_t hash_count = 1'000;
  constexpr auto third = hash_count / 3;
  constexpr auto two_thirds = 2 * hash_count / 3;
  std::vector<std::pair<size_t, size_t>> flush_retract = {
    {0, hash_count},
    {third, two_thirds},
    {third + 1, two_thirds},
    {third, two_thirds + 1}};
  for (auto [flush_index, retract_index] : flush_retract)
  {
    ccf::MerkleTreeHistory original_tree;
    for (size_t i = 0; i < hash_count; ++i)
    {
      auto h = rand_hash();
      original_tree.append(h);
    }
    original_tree.flush(flush_index);
    original_tree.retract(retract_index);

    const auto serialised = original_tree.serialise();

    ccf::MerkleTreeHistory deser_tree(serialised);

    REQUIRE(deser_tree.begin_index() == original_tree.begin_index());
    REQUIRE(deser_tree.end_index() == original_tree.end_index());
    REQUIRE(deser_tree.get_root() == original_tree.get_root());

    for (size_t i = deser_tree.begin_index(); i <= deser_tree.end_index(); ++i)
    {
      REQUIRE(deser_tree.get_hash(i) == original_tree.get_hash(i));
    }
  }
}

TEST_CASE("First root")
{
  {
    INFO("Empty root");
    ccf::MerkleTreeHistory tree;
    const auto empty_root = tree.get_root();
    REQUIRE(empty_root == crypto::Sha256Hash());
    REQUIRE(tree.get_hash(0) == empty_root);
  }

  {
    INFO("Single root");
    const auto h = rand_hash();
    ccf::MerkleTreeHistory tree(h);
    const auto single_root = tree.get_root();
    REQUIRE(single_root == h);
    REQUIRE(tree.get_hash(0) == single_root);
  }
}

// TEST_CASE("Index independence 1")
// {
//   ccf::MerkleTreeHistory tree1;
//   for (size_t i = 0; i < 5; ++i)
//   {
//     auto h = rand_hash();
//     tree1.append(h);
//   }

//   tree1.flush(tree1.end_index());
//   tree1.print();
//   ccf::MerkleTreeHistory tree2(tree1.get_root());
//   REQUIRE(tree1.get_root() == tree2.get_root());
//   tree2.print();

//   for (size_t i = 0; i < 5; ++i)
//   {
//     const auto h = rand_hash();
//     {
//       auto h1 = h;
//       tree1.append(h1);
//     }
//     {
//       auto h2 = h;
//       tree2.append(h2);
//     }
//     std::cout << "Checking after " << i << " appends" << std::endl;
//     tree1.print();
//     tree2.print();
//     REQUIRE(tree1.get_root() == tree2.get_root());
//   }
// }

// TEST_CASE("Index independence 2")
// {
//   std::map<uint64_t, crypto::Sha256Hash> hashes;
//   for (uint64_t i = 0; i < 10; ++i)
//   {
//     hashes[i] = rand_hash();
//   }

//   std::vector<std::unique_ptr<ccf::MerkleTreeHistory>> trees;
//   for (size_t i = 0; i < hashes.size(); ++i)
//   {
//     trees.emplace_back(std::make_unique<ccf::MerkleTreeHistory>());

//     if (i > 0)
//     {
//       // Start later trees from the root of previous tree
//       auto& tree = trees.back();
//       auto& prev = trees[i - 1];
//       auto root = prev->get_root();
//       tree->append(root);
//     }

//     for (auto& tree : trees)
//     {
//       auto h = hashes[i];
//       tree->append(h);
//     }

//     const auto first_root = trees[0]->get_root();
//     for (auto& tree : trees)
//     {
//       REQUIRE(tree->get_root() == first_root);
//     }
//   }
// }
