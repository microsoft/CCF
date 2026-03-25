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
    /// Sequence number of the latest globally committed snapshot baseline
    ccf::kv::Version version = 0;
    /// Timestamp at which that globally committed snapshot was scheduled
    /// (nanoseconds since Unix epoch)
    uint64_t timestamp = 0;
  };

  DECLARE_JSON_TYPE(SnapshotStatus);
  DECLARE_JSON_REQUIRED_FIELDS(SnapshotStatus, version, timestamp);

  using SnapshotStatusValue = ServiceValue<SnapshotStatus>;
  using SnapshotCreate = ServiceValue<uint64_t>;
  namespace Tables
  {
    static constexpr auto SNAPSHOT_STATUS =
      "public:ccf.internal.snapshot_status";
    static constexpr auto SNAPSHOT_CREATE =
      "public:ccf.internal.snapshot_create";
  }
}
