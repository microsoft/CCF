// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"
#include "node_signature.h"

#include <string>
#include <vector>

namespace ccf
{
  struct BackupSignatures
  {
    ccf::View view = 0;
    ccf::SeqNo seqno = 0;
    ccf::crypto::Sha256Hash root;
    std::vector<NodeSignature> signatures;

    BackupSignatures() = default;

    BackupSignatures(
      ccf::View view_, ccf::SeqNo seqno_, const ccf::crypto::Sha256Hash root_) :
      view(view_),
      seqno(seqno_),
      root(root_)
    {}
  };
  DECLARE_JSON_TYPE(BackupSignatures);
  DECLARE_JSON_REQUIRED_FIELDS(BackupSignatures, view, seqno, root, signatures);

  using BackupSignaturesMap = ServiceValue<BackupSignatures>;
  namespace Tables
  {
    static constexpr auto BACKUP_SIGNATURES =
      "public:ccf.internal.consensus.backup_signatures";
  }
}