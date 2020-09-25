// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "entities.h"
#include "tls/hash.h"

#include <vector>

namespace ccf
{
  struct NodeSignature
  {
    std::vector<uint8_t> sig;
    ccf::NodeId node;
    std::array<uint8_t, 32> hashed_nonce;

    NodeSignature(
      const std::vector<uint8_t>& sig_, NodeId node_, std::array<uint8_t, 32> hashed_nonce_) :
      sig(sig_), node(node_), hashed_nonce(hashed_nonce_)
    {}
    NodeSignature(ccf::NodeId node_, std::array<uint8_t, 32> hashed_nonce_) : node(node_), hashed_nonce(hashed_nonce_) {}
    NodeSignature() = default;

    bool operator==(const NodeSignature& o) const
    {
      return sig == o.sig && node == o.node && hashed_nonce == o.hashed_nonce;
    }

    MSGPACK_DEFINE(sig, node, hashed_nonce);
  };
  DECLARE_JSON_TYPE(NodeSignature);
  DECLARE_JSON_REQUIRED_FIELDS(NodeSignature, sig, node, hashed_nonce);
}