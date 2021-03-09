// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "kv/map.h"
#include "node_signature.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  struct PrimarySignature : public NodeSignature
  {
    kv::Consensus::SeqNo seqno = 0;
    kv::Consensus::View view = 0;
    ObjectId commit_seqno = 0;
    ObjectId commit_view = 0;
    crypto::Sha256Hash root;
    std::vector<uint8_t> tree = {0};

    MSGPACK_DEFINE(
      MSGPACK_BASE(NodeSignature),
      seqno,
      view,
      commit_seqno,
      commit_view,
      root,
      tree);

    PrimarySignature() {}

    PrimarySignature(const ccf::NodeId& node_, kv::Consensus::SeqNo seqno_) :
      NodeSignature(node_),
      seqno(seqno_)
    {}

    PrimarySignature(const crypto::Sha256Hash& root_) : root(root_) {}

    PrimarySignature(
      const ccf::NodeId& node_,
      kv::Consensus::SeqNo seqno_,
      kv::Consensus::View view_,
      kv::Consensus::SeqNo commit_seqno_,
      kv::Consensus::View commit_view_,
      const crypto::Sha256Hash root_,
      Nonce hashed_nonce_,
      const std::vector<uint8_t>& sig_,
      const std::vector<uint8_t>& tree_) :
      NodeSignature(sig_, node_, hashed_nonce_),
      seqno(seqno_),
      view(view_),
      commit_seqno(commit_seqno_),
      commit_view(commit_view_),
      root(root_),
      tree(tree_)
    {}
  };
  DECLARE_JSON_TYPE_WITH_BASE(PrimarySignature, NodeSignature)
  DECLARE_JSON_REQUIRED_FIELDS(
    PrimarySignature, seqno, view, commit_seqno, commit_view, root, tree)
  using Signatures = kv::Map<ObjectId, PrimarySignature>;
}