// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "kv/compacted_version_conflict.h"

#include <cstddef>
#include <string_view>

namespace ccf
{
  // Runs fn, retrying a bounded number of times if it throws
  // kv::CompactedVersionConflict.
  //
  // A transaction captures its read version when its first handle is created,
  // and creating a later handle throws if the store has since been compacted
  // past that version. Transactions executed by an endpoint are re-executed by
  // the frontend when this happens, but transactions run elsewhere, such as on
  // a task worker, have no such safety net and the exception would take the
  // node down. Such callers should keep handle creation close together and
  // wrap it in this helper. Each call to fn must create a fresh transaction.
  //
  // fn completes successfully at most once, but may be partially executed
  // multiple times. Avoid externally visible side effects, such as committing
  // a transaction or recording results, until all required handles have been
  // acquired.
  // Attempts are made back to back without any backoff, as the conflict
  // window is only as long as the time between handle creations.
  //
  // Returns true if fn completed, false if every attempt conflicted. Any other
  // exception propagates to the caller unchanged.
  template <typename Fn>
  [[nodiscard]] bool retry_on_compacted_version_conflict(
    std::string_view description, Fn fn)
  {
    constexpr std::size_t max_attempts = 3;
    for (std::size_t attempt = 1; attempt <= max_attempts; ++attempt)
    {
      try
      {
        fn();
        return true;
      }
      catch (const kv::CompactedVersionConflict& e)
      {
        LOG_INFO_FMT(
          "{} conflicted with compaction on attempt {}/{}: {}",
          description,
          attempt,
          max_attempts,
          e.what());
      }
    }

    return false;
  }
}
