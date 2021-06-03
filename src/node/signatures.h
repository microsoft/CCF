// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "node_signature.h"
#include "service_map.h"

#include <string>
#include <vector>

namespace ccf
{
  struct PrimarySignature : public NodeSignature
  {
    /// Sequence number of the signature transaction
    ccf::SeqNo seqno = 0;
    /// View of the signature transaction
    ccf::View view = 0;
    /// Committed sequence number when the signature transaction was emitted
    ccf::SeqNo commit_seqno = 0;
    /** View of the committed sequence number when the signature transaction was
        emitted */
    ccf::View commit_view = 0;
    /// Root of the Merkle Tree as of seqno - 1
    crypto::Sha256Hash root;

    PrimarySignature() {}

    PrimarySignature(const ccf::NodeId& node_, ccf::SeqNo seqno_) :
      NodeSignature(node_),
      seqno(seqno_)
    {}

    PrimarySignature(const crypto::Sha256Hash& root_) : root(root_) {}

    PrimarySignature(
      const ccf::NodeId& node_,
      ccf::SeqNo seqno_,
      ccf::View view_,
      ccf::SeqNo commit_seqno_,
      ccf::View commit_view_,
      const crypto::Sha256Hash root_,
      Nonce hashed_nonce_,
      const std::vector<uint8_t>& sig_) :
      NodeSignature(sig_, node_, hashed_nonce_),
      seqno(seqno_),
      view(view_),
      commit_seqno(commit_seqno_),
      commit_view(commit_view_),
      root(root_)
    {}
  };
  DECLARE_JSON_TYPE_WITH_BASE(PrimarySignature, NodeSignature)
  DECLARE_JSON_REQUIRED_FIELDS(
    PrimarySignature, seqno, view, commit_seqno, commit_view, root)

  // Most recent signature is a single Value in the KV
  using Signatures = ServiceValue<PrimarySignature>;

  // Serialised Merkle tree at most recent signature is a single Value in the KV
  using SerialisedMerkleTree = kv::RawCopySerialisedValue<std::vector<uint8_t>>;
}