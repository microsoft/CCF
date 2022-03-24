// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/json.h"
#include "ccf/entity_id.h"

namespace ccf
{
  struct Receipt
  {
    struct Element
    {
      std::optional<std::string> left = std::nullopt;
      std::optional<std::string> right = std::nullopt;
    };

    struct LeafComponents
    {
      std::optional<std::string> write_set_digest = std::nullopt;
      std::optional<std::string> commit_evidence = std::nullopt;
      std::optional<std::string> claims_digest = std::nullopt;

      LeafComponents() {}
      LeafComponents(
        const std::optional<std::string>& write_set_digest_,
        const std::optional<std::string>& commit_evidence_,
        const std::optional<std::string>& claims_digest_) :
        write_set_digest(write_set_digest_),
        commit_evidence(commit_evidence_),
        claims_digest(claims_digest_)
      {}

      bool operator==(const LeafComponents& other) const = default;
    };

    /// Signature over the root of the Merkle Tree, by the node private key
    std::string signature;
    /// Root of the Merkle Tree
    std::optional<std::string> root = std::nullopt;
    /// Merkle proof from the signed root to the leaf components
    std::vector<Element> proof = {};
    /// Node identity that produced the signature at the time
    ccf::NodeId node_id;
    /// Node identity as a PEM certificate
    std::optional<std::string> cert = std::nullopt;
    // In practice, either leaf or leaf_components is set
    /// Leaf of the Merkle proof, only set on transactions emitted by 1.x
    /// networks. Corresponds to the write set digest.
    std::optional<std::string> leaf = std::nullopt;
    /// Leaf components in transactions emitted by 2.x networks.
    std::optional<LeafComponents> leaf_components = std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Receipt::Element)
  DECLARE_JSON_REQUIRED_FIELDS(Receipt::Element)
  DECLARE_JSON_OPTIONAL_FIELDS(Receipt::Element, left, right)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Receipt::LeafComponents)
  DECLARE_JSON_REQUIRED_FIELDS(Receipt::LeafComponents)
  DECLARE_JSON_OPTIONAL_FIELDS(
    Receipt::LeafComponents, write_set_digest, commit_evidence, claims_digest)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Receipt)
  DECLARE_JSON_REQUIRED_FIELDS(Receipt, signature, proof, node_id)
  DECLARE_JSON_OPTIONAL_FIELDS(Receipt, root, cert, leaf, leaf_components)
}
