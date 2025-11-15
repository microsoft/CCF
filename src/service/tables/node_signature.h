// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ds/serialized.h"

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

    [[nodiscard]] size_t get_serialized_size() const
    {
      return sizeof(size_t) + sig.size() + sizeof(size_t) + node.size() +
        sizeof(hashed_nonce);
    }

    void serialize(uint8_t*& data, size_t& size) const
    {
      size_t sig_size = sig.size();
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&sig_size), sizeof(sig_size));
      serialized::write(data, size, sig.data(), sig_size);

      serialized::write(data, size, node.value());
      serialized::write(
        data,
        size,
        reinterpret_cast<const uint8_t*>(&hashed_nonce),
        sizeof(hashed_nonce));
    }

    static NodeSignature deserialize(const uint8_t*& data, size_t& size)
    {
      NodeSignature n;

      auto sig_size = serialized::read<size_t>(data, size);
      n.sig = serialized::read(data, size, sig_size);
      n.node = serialized::read<NodeId::Value>(data, size);
      n.hashed_nonce = serialized::read<Nonce>(data, size);

      return n;
    }
  };
  DECLARE_JSON_TYPE(NodeSignature);
  DECLARE_JSON_REQUIRED_FIELDS(NodeSignature, sig, node, hashed_nonce);
}