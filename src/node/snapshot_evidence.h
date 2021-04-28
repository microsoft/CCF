// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "ds/json.h"
#include "entities.h"
#include "kv/kv_types.h"
#include "service_map.h"

namespace ccf
{
  struct SnapshotHash
  {
    /// Snapshot digest
    crypto::Sha256Hash hash;
    /// Sequence number to which the snapshot corresponds
    kv::Version version;
  };

  DECLARE_JSON_TYPE(SnapshotHash)
  DECLARE_JSON_REQUIRED_FIELDS(SnapshotHash, hash, version)

  // As we only keep track of the latest snapshot, the key for the
  // SnapshotEvidence table is always 0.
  using SnapshotEvidence = ServiceMap<size_t, SnapshotHash>;
}