// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "kv/compacted_version_conflict.h"

#include <cstddef>

namespace ccf::node
{
  template <typename Lookup>
  bool retry_backup_snapshot_lookup(Lookup&& lookup)
  {
    constexpr std::size_t max_attempts = 3;
    for (std::size_t attempt = 1; attempt <= max_attempts; ++attempt)
    {
      try
      {
        lookup();
        return true;
      }
      catch (const ccf::kv::CompactedVersionConflict& e)
      {
        LOG_DEBUG_FMT(
          "BackupSnapshotFetch: Primary node lookup conflicted with "
          "compaction on attempt {}/{}: {}",
          attempt,
          max_attempts,
          e.what());
      }
    }

    return false;
  }
}
