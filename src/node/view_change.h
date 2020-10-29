// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "kv/map.h"
#include "node_signature.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  struct ViewChange
  {
    kv::Consensus::View view = 0;
    kv::Consensus::SeqNo seqno = 0;
    crypto::Sha256Hash root;

    std::vector<NodeSignature> signatures;

    std::vector<uint8_t> signature;

    ViewChange() = default;
    ViewChange(
      kv::Consensus::View view_,
      kv::Consensus::SeqNo seqno_,
      crypto::Sha256Hash root_) :
      view(view_),
      seqno(seqno_),
      root(root_)
    {}

    size_t get_serialized_size() const
    {
      size_t size = sizeof(view) + sizeof(seqno) + sizeof(root) +
        sizeof(size_t) + sizeof(size_t) + signature.size();

      for (const auto& s : signatures)
      {
        size += s.get_serialized_size();
      }
      return size;
    }

    void serialize(uint8_t*& data, size_t& size)
    {
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&view), sizeof(view));
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&seqno), sizeof(seqno));
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&root), sizeof(root));

      size_t num_sigs = signatures.size();
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&num_sigs), sizeof(num_sigs));

      for (const auto& s : signatures)
      {
        s.serialize(data, size);
      }

      size_t sig_size = signature.size();
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&sig_size), sizeof(sig_size));
      serialized::write(data, size, signature.data(), sig_size);
    }

    static ViewChange deserialize(const uint8_t*& data, size_t& size)
    {
      ViewChange v;

      v.view = serialized::read<kv::Consensus::View>(data, size);
      v.seqno = serialized::read<kv::Consensus::SeqNo>(data, size);
      v.root = serialized::read<crypto::Sha256Hash>(data, size);

      size_t num_sigs = serialized::read<size_t>(data, size);
      for (size_t i = 0; i < num_sigs; ++i)
      {
        v.signatures.push_back(ccf::NodeSignature::deserialize(data, size));
      }

      size_t sig_size = serialized::read<size_t>(data, size);
      v.signature = serialized::read(data, size, sig_size);

      return v;
    }
  };
}