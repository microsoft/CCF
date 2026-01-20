// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"
#include "node_signature.h"

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
    // DEPRECATED: These are no longer populated, and will always be 0
    ccf::SeqNo commit_seqno = 0;
    ccf::View commit_view = 0;
    /// Root of the Merkle Tree as of seqno - 1
    ccf::crypto::Sha256Hash root;
    /// Service-endorsed certificate of the node which produced the signature
    ccf::crypto::Pem cert;

    PrimarySignature() = default;

    PrimarySignature(ccf::NodeId node_, ccf::SeqNo seqno_) :
      NodeSignature(std::move(node_)),
      seqno(seqno_)
    {}

    PrimarySignature(ccf::crypto::Sha256Hash root_) : root(std::move(root_)) {}

    PrimarySignature(
      const ccf::NodeId& node_,
      ccf::SeqNo seqno_,
      ccf::View view_,
      const ccf::crypto::Sha256Hash root_,
      Nonce hashed_nonce_,
      const std::vector<uint8_t>& sig_,
      ccf::crypto::Pem cert_) :
      NodeSignature(sig_, node_, hashed_nonce_),
      seqno(seqno_),
      view(view_),
      root(root_),
      cert(std::move(cert_))
    {}
  };
  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(
    PrimarySignature, NodeSignature);
  DECLARE_JSON_REQUIRED_FIELDS(
    PrimarySignature, seqno, view, commit_seqno, commit_view, root);
  DECLARE_JSON_OPTIONAL_FIELDS(PrimarySignature, cert);

  // Most recent signature is a single Value in the KV
  using Signatures = ServiceValue<PrimarySignature>;

  // Serialised Merkle tree at most recent signature is a single Value in the KV
  using SerialisedMerkleTree =
    ccf::kv::RawCopySerialisedValue<std::vector<uint8_t>>;

  using CoseSignature = std::vector<uint8_t>;

  // Most recent COSE signature is a single Value in the KV
  using CoseSignatures = ServiceValue<CoseSignature>;

  namespace Tables
  {
    static constexpr auto SIGNATURES = "public:ccf.internal.signatures";
    static constexpr auto COSE_SIGNATURES =
      "public:ccf.internal.cose_signatures";
    static constexpr auto SERIALISED_MERKLE_TREE = "public:ccf.internal.tree";
  }
}