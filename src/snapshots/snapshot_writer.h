// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "consensus/ledger_enclave_types.h"
#include "ds/files.h"
#include "host/time_bound_logger.h"
#include "snapshots/filenames.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <unistd.h>
#include <vector>

namespace snapshots
{
  namespace fs = std::filesystem;

  // Writes committed snapshot files to disk.
  class SnapshotWriter
  {
  private:
    const fs::path snapshot_dir;

  public:
    explicit SnapshotWriter(const std::string& snapshot_dir_) :
      snapshot_dir(snapshot_dir_)
    {
      if (fs::is_directory(snapshot_dir))
      {
        LOG_INFO_FMT(
          "Snapshots will be stored in existing directory: {}", snapshot_dir);
      }
      else if (!fs::create_directory(snapshot_dir))
      {
        throw std::logic_error(
          fmt::format("Could not create snapshot directory: {}", snapshot_dir));
      }
    }

    SnapshotWriter(const SnapshotWriter&) = delete;
    SnapshotWriter& operator=(const SnapshotWriter&) = delete;

    void persist_snapshot(
      ::consensus::Index snapshot_idx,
      ::consensus::Index evidence_idx,
      const std::vector<uint8_t>& snapshot,
      const std::vector<uint8_t>& receipt)
    {
      asynchost::TimeBoundLogger log_if_slow(
        fmt::format("Committing snapshot - snapshot_idx={}", snapshot_idx));

      // e.g. snapshot_100_105
      auto file_name = fmt::format(
        "{}{}{}{}{}",
        snapshot_file_prefix,
        snapshot_idx_delimiter,
        snapshot_idx,
        snapshot_idx_delimiter,
        evidence_idx);
      auto full_snapshot_path = snapshot_dir / file_name;

      int snapshot_fd = -1;

      try
      {
        snapshot_fd =
          files::open_fd(full_snapshot_path, O_CREAT | O_EXCL | O_WRONLY);
        if (snapshot_fd == -1)
        {
          if (errno == EEXIST)
          {
            // In the case that a file with this name already exists, keep the
            // existing file and drop this snapshot
            LOG_FAIL_FMT(
              "Cannot write snapshot as file already exists: {}", file_name);
          }
          else
          {
            LOG_FAIL_FMT(
              "Cannot write snapshot: error ({}) opening file {}",
              errno,
              file_name);
          }
          return;
        }

        auto remove_incomplete_file = [&]() {
          close_fd(snapshot_fd, file_name);
          snapshot_fd = -1;

          std::error_code ec;
          fs::remove(full_snapshot_path, ec);
          if (ec)
          {
            LOG_FAIL_FMT(
              "Failed to remove incomplete snapshot file {}: {}",
              file_name,
              ec.message());
          }
        };

        if (
          !write_all(
            snapshot_fd, file_name, snapshot.data(), snapshot.size()) ||
          !write_all(snapshot_fd, file_name, receipt.data(), receipt.size()))
        {
          remove_incomplete_file();
          return;
        }

        LOG_INFO_FMT(
          "New snapshot file written to {} [{} bytes] (unsynced)",
          file_name,
          snapshot.size() + receipt.size());

        {
          asynchost::TimeBoundLogger log_sync_if_slow(
            fmt::format("Syncing snapshot - fsync({})", file_name));
          // NOLINTNEXTLINE(concurrency-mt-unsafe)
          if (fsync(snapshot_fd) == -1)
          {
            LOG_FAIL_FMT(
              "Error ({}) syncing snapshot {}",
              strerror(errno), // NOLINT(concurrency-mt-unsafe)
              file_name);
            remove_incomplete_file();
            return;
          }
        }

        close_fd(snapshot_fd, file_name);
        snapshot_fd = -1;

        // e.g. snapshot_100_105.committed
        auto committed_file_name =
          fmt::format("{}{}", file_name, snapshot_committed_suffix);
        {
          asynchost::TimeBoundLogger log_rename_if_slow(fmt::format(
            "Renaming snapshot to committed - rename({})", file_name));
          files::rename(
            snapshot_dir / file_name, snapshot_dir / committed_file_name);
        }

        LOG_INFO_FMT(
          "Renamed snapshot {} to {}", file_name, committed_file_name);
      }
      catch (const std::exception& e)
      {
        if (snapshot_fd != -1)
        {
          close_fd(snapshot_fd, file_name);
        }

        LOG_FAIL_FMT(
          "Exception while attempting to persist snapshot at {}: {}",
          snapshot_idx,
          e.what());
      }
    }

  private:
    static bool write_all(
      int fd, const std::string& file_name, const uint8_t* data, size_t size)
    {
      asynchost::TimeBoundLogger log_if_slow(fmt::format(
        "Writing snapshot data ({} bytes) - write({})", size, file_name));

      size_t offset = 0;
      while (offset < size)
      {
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        auto rc = write(fd, data + offset, size - offset);
        if (rc == -1)
        {
          if (errno == EINTR)
          {
            continue;
          }

          LOG_FAIL_FMT(
            "Error ({}) writing snapshot {}",
            strerror(errno), // NOLINT(concurrency-mt-unsafe)
            file_name);
          return false;
        }

        if (rc == 0)
        {
          LOG_FAIL_FMT(
            "Unexpected short write while writing snapshot {}", file_name);
          return false;
        }

        offset += static_cast<size_t>(rc);
      }

      return true;
    }

    static void close_fd(int fd, const std::string& file_name)
    {
      // NOLINTNEXTLINE(concurrency-mt-unsafe)
      if (close(fd) == -1)
      {
        LOG_FAIL_FMT(
          "Error ({}) closing snapshot {}",
          strerror(errno), // NOLINT(concurrency-mt-unsafe)
          file_name);
      }
    }
  };
}
