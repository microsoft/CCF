// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include "ccf/crypto/openssl_init.h"

#include <doctest/doctest.h>

ccf::crypto::Sha256Hash rand_hash()
{
  ccf::crypto::Sha256Hash hash;
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

TEST_CASE("Retrieving leaves")
{
  constexpr size_t hash_count = 1'000;

  std::map<uint64_t, ccf::crypto::Sha256Hash> hashes;
  hashes[0] =
    ccf::crypto::Sha256Hash(); // Default index 0 always contains all-0s

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
    auto& hash_ = hash;
    const auto h = history.get_leaf(i);
    REQUIRE(h == hash_);
  }

  for (const auto& [i, hash] : hashes)
  {
    auto& hash_ = hash;
    history.flush(i);
    const auto h = history.get_leaf(i);
    REQUIRE(h == hash_);
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
      REQUIRE(deser_tree.get_leaf(i) == original_tree.get_leaf(i));
    }

    auto h = rand_hash();
    auto h1 = h; // tree.append(h) modifies h so we take a copy
    original_tree.append(h);
    deser_tree.append(h1);
    REQUIRE(original_tree.get_root() == deser_tree.get_root());
  }
}

TEST_CASE("First root")
{
  {
    INFO("Empty root");
    ccf::MerkleTreeHistory tree;
    const auto empty_root = tree.get_root();
    REQUIRE(empty_root == ccf::crypto::Sha256Hash());
    REQUIRE(tree.get_leaf(0) == empty_root);
  }

  {
    INFO("Single root");
    const auto h = rand_hash();
    ccf::MerkleTreeHistory tree(h);
    const auto single_root = tree.get_root();
    REQUIRE(single_root == h);
    REQUIRE(tree.get_leaf(0) == single_root);
  }
}

int main(int argc, char** argv)
{
  ccf::crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  ccf::crypto::openssl_sha256_shutdown();
  return res;
}
