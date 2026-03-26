// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "snapshots/snapshot_manager.h"
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
      snapshots::SnapshotManager::cleanup_old_snapshots(dir, max_retained);
    }
  };

  using SnapshotCleanupTimer = proxy_ptr<Timer<SnapshotCleanupImpl>>;
}
