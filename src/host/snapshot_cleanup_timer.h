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

    struct CleanupWork
    {
      std::filesystem::path dir;
      size_t max_retained;
    };

    static void cleanup_old_snapshots(
      const std::filesystem::path& dir, size_t max_retained)
    {
      std::vector<std::filesystem::path> directories{dir};
      decltype(snapshots::find_committed_snapshots_in_directories(
        directories)) committed;
      try
      {
        committed =
          snapshots::find_committed_snapshots_in_directories(directories);
      }
      catch (const std::filesystem::filesystem_error& e)
      {
        LOG_FAIL_FMT(
          "Failed to list committed snapshots in {}: {}", dir, e.what());
        return;
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Unexpected error while listing committed snapshots in {}: {}",
          dir,
          e.what());
        return;
      }

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

    static void on_cleanup_work(uv_work_t* req)
    {
      auto* work = static_cast<CleanupWork*>(req->data);
      cleanup_old_snapshots(work->dir, work->max_retained);
    }

    static void on_cleanup_work_done(uv_work_t* req, int /*status*/)
    {
      auto* work = static_cast<CleanupWork*>(req->data);
      LOG_DEBUG_FMT("Snapshot cleanup completed");
      delete work; // NOLINT(cppcoreguidelines-owning-memory)
      delete req; // NOLINT(cppcoreguidelines-owning-memory)
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
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* work = new CleanupWork{.dir = dir, .max_retained = max_retained};
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* req = new uv_work_t;
      req->data = work;
      int rc = uv_queue_work(
        uv_default_loop(), req, &on_cleanup_work, &on_cleanup_work_done);
      if (rc < 0)
      {
        LOG_FAIL_FMT(
          "Failed to queue snapshot cleanup work: {}", uv_strerror(rc));
        delete work; // NOLINT(cppcoreguidelines-owning-memory)
        delete req; // NOLINT(cppcoreguidelines-owning-memory)
      }
    }
  };

  using SnapshotCleanupTimer = proxy_ptr<Timer<SnapshotCleanupImpl>>;
}
