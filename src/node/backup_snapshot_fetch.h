// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "kv/compacted_version_conflict.h"

#include <cstddef>

namespace ccf::node
{
  // Retries a read-only KV lookup that may throw CompactedVersionConflict
  // when compaction races the lazily captured read version. Each call to
  // lookup must create a fresh transaction. Attempts are made back to back
  // without any backoff: the conflict window only spans the time between
  // capturing the read version and creating the change set, so an immediate
  // retry is sufficient.
  template <typename Lookup>
  bool retry_backup_snapshot_lookup(Lookup lookup)
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
