// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/entity_id.h"
#include "crypto/hash.h"
#include "ds/json.h"

namespace ccf
{
  struct Receipt
  {
    struct Element
    {
      std::optional<std::string> left = std::nullopt;
      std::optional<std::string> right = std::nullopt;
    };

    std::string signature;
    std::optional<std::string> root = std::nullopt;
    std::vector<Element> proof = {};
    std::string leaf;
    ccf::NodeId node_id;
    std::optional<std::string> cert = std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Receipt::Element)
  DECLARE_JSON_REQUIRED_FIELDS(Receipt::Element);
  DECLARE_JSON_OPTIONAL_FIELDS(Receipt::Element, left, right)
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Receipt)
  DECLARE_JSON_REQUIRED_FIELDS(Receipt, signature, proof, leaf, node_id)
  DECLARE_JSON_OPTIONAL_FIELDS(Receipt, root, cert)

  static crypto::Sha256Hash compute_root_from_receipt(const Receipt& receipt)
  {
    crypto::Sha256Hash current = receipt.leaf;
    for (auto const& element : receipt.proof)
    {
      if (element.left.has_value())
      {
        assert(!element.right.has_value());
        crypto::Sha256Hash left = element.left.value();
        current = crypto::Sha256Hash(left, current);
      }
      else
      {
        assert(element.right.has_value());
        crypto::Sha256Hash right = element.right.value();
        current = crypto::Sha256Hash(current, right);
      }
    }

    return current;
  }
}