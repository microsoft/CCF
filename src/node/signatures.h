// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "entities.h"
#include "kv/map.h"
#include "raw_signature.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  struct Signature : public RawSignature
  {
    NodeId node;
    ObjectId seqno;
    ObjectId view;
    ObjectId commit;
    crypto::Sha256Hash root;
    std::vector<uint8_t> tree;

    MSGPACK_DEFINE(
      MSGPACK_BASE(RawSignature), node, seqno, view, commit, root, tree);

    Signature() {}

    Signature(NodeId node_, ObjectId seqno_) :
      node(node_),
      seqno(seqno_),
      view(0),
      commit(0)
    {}

    Signature(const crypto::Sha256Hash& root_) :
      node(0),
      seqno(0),
      view(0),
      commit(0),
      root(root_),
      tree{0}
    {}

    Signature(
      NodeId node_,
      ObjectId seqno_,
      ObjectId view_,
      ObjectId commit_,
      const crypto::Sha256Hash root_,
      const std::vector<uint8_t>& sig_,
      const std::vector<uint8_t>& tree_) :
      RawSignature{sig_},
      node(node_),
      seqno(seqno_),
      view(view_),
      commit(commit_),
      root(root_),
      tree(tree_)
    {}
  };
  DECLARE_JSON_TYPE_WITH_BASE(Signature, RawSignature)
  DECLARE_JSON_REQUIRED_FIELDS(Signature, node, seqno, view, commit, root)
  using Signatures = kv::Map<ObjectId, Signature>;
}