// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/json.h"
#include "ccf/entity_id.h"
#include "crypto/hash.h"

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

    std::string signature;
    std::optional<std::string> root = std::nullopt;
    std::vector<Element> proof = {};
    ccf::NodeId node_id;
    std::optional<std::string> cert = std::nullopt;
    // In practice, either leaf or leaf_components is set
    std::optional<std::string> leaf = std::nullopt;
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

  /* Receipts included in snapshots always contain leaf components,
     including a claims digest and commit evidence, from 2.0.0-rc0 onwards.
     This verification code deliberately does not support snapshots
     produced by 2.0.0-dev* releases
  */
  static crypto::Sha256Hash compute_root_from_snapshot_receipt(
    const Receipt& receipt)
  {
    crypto::Sha256Hash current;
    if (receipt.leaf_components.has_value())
    {
      auto components = receipt.leaf_components.value();
      if (
        components.write_set_digest.has_value() &&
        components.commit_evidence.has_value() &&
        components.claims_digest.has_value())
      {
        auto ws_dgst = crypto::Sha256Hash::from_hex_string(
          components.write_set_digest.value());
        crypto::Sha256Hash ce_dgst(components.commit_evidence.value());
        auto cl_dgst =
          crypto::Sha256Hash::from_hex_string(components.claims_digest.value());
        current = crypto::Sha256Hash(ws_dgst, ce_dgst, cl_dgst);
      }
      else
      {
        throw std::logic_error(
          "Cannot compute leaf unless write_set_digest, commit_evidence and "
          "claims_digest "
          "are set");
      }
    }
    else
    {
      throw std::logic_error(
        "Cannot compute root if leaf_components are not set");
    }
    for (auto const& element : receipt.proof)
    {
      if (element.left.has_value())
      {
        assert(!element.right.has_value());
        auto left = crypto::Sha256Hash::from_hex_string(element.left.value());
        current = crypto::Sha256Hash(left, current);
      }
      else
      {
        assert(element.right.has_value());
        auto right = crypto::Sha256Hash::from_hex_string(element.right.value());
        current = crypto::Sha256Hash(current, right);
      }
    }

    return current;
  }
}