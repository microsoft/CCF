// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "entities.h"

#include <vector>

namespace ccf
{
  struct NodeSignature
  {
    std::vector<uint8_t> sig;
    ccf::NodeId node;

    NodeSignature(const std::vector<uint8_t>& sig_, NodeId node_) :
      sig(sig_),
      node(node_)
    {}
    NodeSignature(ccf::NodeId node_) : node(node_) {}
    NodeSignature() = default;

    bool operator==(const NodeSignature& o) const
    {
      return sig == o.sig;
    }

    MSGPACK_DEFINE(sig, node);
  };
  DECLARE_JSON_TYPE(NodeSignature);
  DECLARE_JSON_REQUIRED_FIELDS(NodeSignature, sig, node);
}