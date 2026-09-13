// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <vector>

namespace ccf
{
  using Nonce = ccf::crypto::Sha256Hash;

  struct NodeSignature
  {
    /// Signature
    std::vector<uint8_t> sig;
    /// Node ID
    NodeId node;
    /// Hashed nonce created by the node, only used for BFT
    Nonce hashed_nonce;

    NodeSignature(const NodeSignature& ns) = default;
    NodeSignature(
      std::vector<uint8_t> sig_, NodeId node_, Nonce hashed_nonce_) :
      sig(std::move(sig_)),
      node(std::move(node_)),
      hashed_nonce(std::move(hashed_nonce_))
    {}
    NodeSignature(NodeId node_, Nonce hashed_nonce_) :
      node(std::move(node_)),
      hashed_nonce(std::move(hashed_nonce_))
    {}
    NodeSignature(NodeId node_) : node(std::move(node_)) {}
    NodeSignature() = default;

    NodeSignature& operator=(const NodeSignature& ns) = default;

    bool operator==(const NodeSignature& o) const
    {
      return sig == o.sig && hashed_nonce == o.hashed_nonce;
    }
  };
  DECLARE_JSON_TYPE(NodeSignature);
  DECLARE_JSON_REQUIRED_FIELDS(NodeSignature, sig, node, hashed_nonce);
}