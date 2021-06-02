// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "node_signature.h"
#include "service_map.h"

#include <string>
#include <vector>

namespace ccf
{
  struct ViewChangeRequest
  {
    std::vector<NodeSignature> signatures;
    ccf::SeqNo seqno;
    crypto::Sha256Hash root;
    std::vector<uint8_t> signature;

    ViewChangeRequest() = default;

    size_t get_serialized_size() const
    {
      size_t size = sizeof(size_t) + sizeof(size_t) + sizeof(ccf::SeqNo) +
        sizeof(root) + signature.size();

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

      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&seqno), sizeof(seqno));
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&root), sizeof(root));

      size_t sig_size = signature.size();
      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&sig_size), sizeof(sig_size));
      serialized::write(data, size, signature.data(), sig_size);
    }

    static ViewChangeRequest deserialize(const uint8_t*& data, size_t& size)
    {
      ViewChangeRequest v;
      size_t num_sigs = serialized::read<size_t>(data, size);
      for (size_t i = 0; i < num_sigs; ++i)
      {
        v.signatures.push_back(ccf::NodeSignature::deserialize(data, size));
      }

      v.seqno = serialized::read<ccf::SeqNo>(data, size);
      v.root = serialized::read<crypto::Sha256Hash>(data, size);
      size_t sig_size = serialized::read<size_t>(data, size);
      v.signature = serialized::read(data, size, sig_size);

      return v;
    }
  };
  DECLARE_JSON_TYPE(ViewChangeRequest);
  DECLARE_JSON_REQUIRED_FIELDS(
    ViewChangeRequest, signatures, seqno, root, signature);

  struct ViewChangeConfirmation
  {
    ccf::View view = 0;
    std::vector<uint8_t> signature;

    std::map<NodeId, ViewChangeRequest> view_change_messages;

    ViewChangeConfirmation() = default;
    ViewChangeConfirmation(ccf::View view_) : view(view_) {}
  };
  DECLARE_JSON_TYPE(ViewChangeConfirmation);
  DECLARE_JSON_REQUIRED_FIELDS(
    ViewChangeConfirmation, view, signature, view_change_messages);

  // Always recorded at key 0
  using NewViewsMap = ServiceMap<size_t, ViewChangeConfirmation>;
}