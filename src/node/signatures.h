// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "entities.h"
#include "raw_signature.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  struct Signature : public RawSignature
  {
    NodeId node;
    ObjectId index;
    ObjectId term;
    ObjectId commit;
    crypto::Sha256Hash root;
    std::vector<uint8_t> tree;

    MSGPACK_DEFINE(
      MSGPACK_BASE(RawSignature), node, index, term, commit, root, tree);

    Signature() {}

    Signature(NodeId node_, ObjectId index_) :
      node(node_),
      index(index_),
      term(0),
      commit(0)
    {}

    Signature(crypto::Sha256Hash root_) :
      node(0),
      index(0),
      term(0),
      commit(0),
      root(root_),
      tree{0}
    {}

    Signature(
      NodeId node_,
      ObjectId index_,
      ObjectId term_,
      ObjectId commit_,
      const crypto::Sha256Hash root_,
      const std::vector<uint8_t>& sig_,
      const std::vector<uint8_t>& tree_) :
      RawSignature{sig_},
      node(node_),
      index(index_),
      term(term_),
      commit(commit_),
      root(root_),
      tree(tree_)
    {}
  };
  DECLARE_JSON_TYPE_WITH_BASE(Signature, RawSignature)
  DECLARE_JSON_REQUIRED_FIELDS(Signature, node, index, term, commit, root)
  using Signatures = Store::Map<ObjectId, Signature>;
}