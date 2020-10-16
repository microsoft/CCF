// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "crypto/hash.h"
#include "ds/logger.h"

#include <doctest/doctest.h>
#include <hacl-star/evercrypt/MerkleTree.h>
#include <string>

TEST_CASE("Test for san")
{
  merkle_tree* src_tree;
  merkle_tree* dst_tree;

  // Note: crypto::Sha256Hash is a thin C++ wrapper around evercrypt_sha256
  crypto::Sha256Hash first_hash = {};
  src_tree = mt_create(first_hash.h.data());

  // Insert one additional hash in first tree
  std::string data = fmt::format("to_be_hashed");
  crypto::Sha256Hash hash(data);
  uint8_t* h = hash.h.data();
  if (!mt_insert_pre(src_tree, h))
  {
    throw std::logic_error("Precondition to mt_insert violated");
  }
  mt_insert(src_tree, h);

  // Serialise first tree
  std::vector<uint8_t> serialised(mt_serialize_size(src_tree));
  mt_serialize(src_tree, serialised.data(), serialised.capacity());

  // Deserialise in second tree
  dst_tree =
    mt_deserialize(serialised.data(), serialised.size(), mt_sha256_compress);

  // Insert two more hashes in second tree
  for (size_t i = 0; i < 2; i++)
  {
    std::string data = fmt::format("to_be_hashed: {}", i);
    crypto::Sha256Hash hash(data);
    uint8_t* h = hash.h.data();
    if (!mt_insert_pre(dst_tree, h))
    {
      throw std::logic_error("Precondition to mt_insert violated");
    }
    // Second insertion raises
    //     ../3rdparty/hacl-star/evercrypt/MerkleTree.c:177:17: runtime error:
    //     null pointer passed as argument 2, which is declared to never be null
    // /usr/include/string.h:43:28: note: nonnull attribute specified here
    // SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior
    // ../3rdparty/hacl-star/evercrypt/MerkleTree.c:177:17 in
    mt_insert(dst_tree, h);
  }

  {
    mt_free(src_tree);
    mt_free(dst_tree);
  }
}