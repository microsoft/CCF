// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "snapshots/filenames.h"
#include "timer.h"

#include <filesystem>
#include <string>

namespace asynchost
{
  class SnapshotCleanupImpl
  {
  private:
    std::filesystem::path dir;
    size_t max_retained;

    static void cleanup_old_snapshots(
      const std::filesystem::path& dir, size_t max_retained)
    {
      std::vector<std::filesystem::path> directories{dir};
      auto committed =
        snapshots::find_committed_snapshots_in_directories(directories);

      if (committed.size() > max_retained)
      {
        // committed is sorted descending by snapshot index, so the
        // oldest are at the end
        for (auto it = committed.rbegin();
             it != committed.rend() - max_retained;
             ++it)
        {
          const auto& path = it->second;
          LOG_INFO_FMT(
            "Deleting old snapshot {} (retaining {})",
            path.filename(),
            max_retained);
          std::error_code ec;
          std::filesystem::remove(path, ec);
          if (ec)
          {
            LOG_FAIL_FMT(
              "Failed to delete old snapshot {}: {}",
              path.filename(),
              ec.message());
          }
        }
      }
    }

  public:
    SnapshotCleanupImpl(const std::string& dir_, size_t max_retained_) :
      dir(dir_),
      max_retained(max_retained_)
    {
      if (max_retained < 1)
      {
        throw std::logic_error(fmt::format(
          "files_cleanup.max_snapshots must be at least 1, got {}",
          max_retained));
      }
    }

    void on_timer()
    {
      cleanup_old_snapshots(dir, max_retained);
    }
  };

  using SnapshotCleanupTimer = proxy_ptr<Timer<SnapshotCleanupImpl>>;
}
