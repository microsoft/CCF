// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "util.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <merklecpp.h>

TEST_CASE("Empty tree")
{
  merkle::Tree tree;

  REQUIRE(tree.empty());
  REQUIRE(tree.min_index() == 0);
  REQUIRE(tree.max_index() == 0);

  REQUIRE_THROWS(tree.root());
  REQUIRE_THROWS(tree.path(0));
  REQUIRE_THROWS(tree.past_root(0));
  REQUIRE_THROWS(tree.past_path(0, 1));

  REQUIRE_NOTHROW(tree.flush_to(0));
  REQUIRE_NOTHROW(tree.retract_to(0));

  std::vector<uint8_t> buffer;
  REQUIRE_NOTHROW(tree.serialise(buffer));
  REQUIRE_NOTHROW(merkle::Tree dt(buffer));
}

TEST_CASE("One-node tree")
{
  merkle::Tree::Hash h;
  merkle::Tree tree(h);

  REQUIRE(tree.min_index() == 0);
  REQUIRE(tree.max_index() == 0);

  REQUIRE(tree.root() == h);
  REQUIRE(tree.leaf(0) == h);
  REQUIRE(*tree.path(0)->root() == h);
  REQUIRE(*tree.past_root(0) == h);
  REQUIRE_THROWS(tree.past_root(1));
  REQUIRE(*tree.past_path(0, 0)->root() == h);
  REQUIRE_THROWS(tree.past_path(0, 1));

  REQUIRE_NOTHROW(tree.flush_to(0));
  REQUIRE_NOTHROW(tree.retract_to(0));

  std::vector<uint8_t> buffer;
  REQUIRE_NOTHROW(tree.serialise(buffer));
  merkle::Tree dt(buffer);
  REQUIRE(dt.root() == tree.root());
}

TEST_CASE("Three-node tree")
{
  merkle::Tree::Hash h0, h1, hr;
  h1.bytes[31] = 1;

  merkle::Tree tree;

  REQUIRE_NOTHROW(tree.insert(h0));
  REQUIRE_NOTHROW(tree.insert(h1));

  hr = tree.root();

  REQUIRE(tree.min_index() == 0);
  REQUIRE(tree.max_index() == 1);

  REQUIRE(tree.leaf(0) == h0);
  REQUIRE(tree.leaf(1) == h1);
  REQUIRE(*tree.path(0)->root() == hr);
  REQUIRE(*tree.past_root(0) == h0);
  REQUIRE(*tree.past_root(1) == hr);
  REQUIRE(*tree.past_root(0) == h0);
  REQUIRE(*tree.past_root(1) == hr);

  auto pp00 = tree.past_path(0, 0);
  REQUIRE(pp00->size() == 0);
  REQUIRE(pp00->leaf() == h0);
  REQUIRE(*pp00->root() == h0);
  REQUIRE(pp00->begin() == pp00->end());

  auto pp01 = tree.past_path(0, 1);
  REQUIRE(pp01->size() == 1);
  REQUIRE(pp01->leaf() == h0);
  REQUIRE((*pp01)[0] == h1);
  auto it = pp01->begin();
  REQUIRE(it->hash == h1);
  REQUIRE(it->direction == merkle::Path::PATH_RIGHT);
  it++;
  REQUIRE(it == pp01->end());
  REQUIRE(*pp01->root() == hr);

  std::vector<uint8_t> buffer;
  REQUIRE_NOTHROW(tree.serialise(buffer));
  merkle::Tree dt(buffer);
  REQUIRE(dt.root() == tree.root());

  merkle::Tree copy = tree;

  REQUIRE_NOTHROW(tree.flush_to(0));
  REQUIRE_NOTHROW(tree.flush_to(1));
  REQUIRE_THROWS(tree.retract_to(0));

  REQUIRE_NOTHROW(copy.flush_to(0));
  REQUIRE_NOTHROW(copy.retract_to(1));
  REQUIRE_NOTHROW(copy.retract_to(0));
  REQUIRE_THROWS(copy.flush_to(1));

  REQUIRE(copy.size() == 1);
  REQUIRE(copy.root() == h0);
}