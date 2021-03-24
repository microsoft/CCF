// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "node_signature.h"
#include "service_map.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  struct BackupSignatures
  {
    ccf::View view = 0;
    ccf::SeqNo seqno = 0;
    crypto::Sha256Hash root;
    std::vector<NodeSignature> signatures;

    MSGPACK_DEFINE(view, seqno, root, signatures);

    BackupSignatures() = default;

    BackupSignatures(
      ccf::View view_,
      ccf::SeqNo seqno_,
      const crypto::Sha256Hash root_) :
      view(view_),
      seqno(seqno_),
      root(root_)
    {}
  };
  DECLARE_JSON_TYPE(BackupSignatures);
  DECLARE_JSON_REQUIRED_FIELDS(BackupSignatures, view, seqno, root, signatures)

  // Always recorded at key 0
  using BackupSignaturesMap = ServiceMap<size_t, BackupSignatures>;
}