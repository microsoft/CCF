// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"
#include "kv/kv_types.h"

namespace ccf
{
  struct SnapshotStatus
  {
    /// Sequence number of the latest snapshot
    ccf::kv::Version version = 0;
    /// Timestamp at which the snapshot was scheduled (nanoseconds since Unix
    /// epoch)
    uint64_t timestamp = 0;
  };

  DECLARE_JSON_TYPE(SnapshotStatus);
  DECLARE_JSON_REQUIRED_FIELDS(SnapshotStatus, version, timestamp);

  using SnapshotStatusValue = ServiceValue<SnapshotStatus>;
  namespace Tables
  {
    static constexpr auto SNAPSHOT_STATUS =
      "public:ccf.internal.snapshot_status";
  }
}
