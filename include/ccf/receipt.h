// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ds/json.h"
#include "kv/kv_types.h" // TODO: ccf::NodeID

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
    std::string root;
    std::vector<Element> proof = {};
    std::string leaf;
    ccf::NodeId node_id;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Receipt::Element)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
  DECLARE_JSON_REQUIRED_FIELDS(Receipt::Element);
#pragma clang diagnostic pop
  DECLARE_JSON_OPTIONAL_FIELDS(Receipt::Element, left, right)
  DECLARE_JSON_TYPE(Receipt)
  DECLARE_JSON_REQUIRED_FIELDS(Receipt, signature, root, proof, leaf, node_id)
}