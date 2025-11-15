// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"
#include "kv/kv_types.h"

namespace ccf
{
  struct SnapshotHash
  {
    /// Snapshot digest
    ccf::crypto::Sha256Hash hash;
    /// Sequence number to which the snapshot corresponds
    ccf::kv::Version version = 0;
  };

  DECLARE_JSON_TYPE(SnapshotHash)
  DECLARE_JSON_REQUIRED_FIELDS(SnapshotHash, hash, version)

  using SnapshotEvidence = ServiceValue<SnapshotHash>;
  namespace Tables
  {
    static constexpr auto SNAPSHOT_EVIDENCE =
      "public:ccf.internal.snapshot_evidence";
  }
}