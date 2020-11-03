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
    std::vector<NodeSignature> signatures;
    std::vector<uint8_t> signature;

    ViewChange() = default;

    size_t get_serialized_size() const
    {
      size_t size = sizeof(size_t) + sizeof(size_t) + signature.size();

      for (const auto& s : signatures)
      {
        size += s.get_serialized_size();
      }
      return size;
    }

    void serialize(uint8_t*& data, size_t& size)
    {
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
      size_t num_sigs = serialized::read<size_t>(data, size);
      for (size_t i = 0; i < num_sigs; ++i)
      {
        v.signatures.push_back(ccf::NodeSignature::deserialize(data, size));
      }

      size_t sig_size = serialized::read<size_t>(data, size);
      v.signature = serialized::read(data, size, sig_size);

      return v;
    }
    MSGPACK_DEFINE(signatures, signature);
  };
  DECLARE_JSON_TYPE(ViewChange);
  DECLARE_JSON_REQUIRED_FIELDS(ViewChange, signatures, signature);

  struct NewView
  {
    kv::Consensus::View view = 0;
    kv::Consensus::SeqNo seqno = 0;
    crypto::Sha256Hash root;

    std::vector<ViewChange> view_change_messages;

    NewView() = default;
    NewView(
      kv::Consensus::View view_,
      kv::Consensus::SeqNo seqno_,
      crypto::Sha256Hash& root_) :
      view(view_), seqno(seqno_), root(root_)
    {}

    MSGPACK_DEFINE(view, seqno, root, view_change_messages);
  };
  DECLARE_JSON_TYPE(NewView);
  DECLARE_JSON_REQUIRED_FIELDS(NewView, view, seqno, root, view_change_messages);

  using NewViewsMap = kv::Map<ObjectId, NewView>;
}