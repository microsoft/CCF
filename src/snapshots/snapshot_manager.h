// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "consensus/ledger_enclave_types.h"
#include "ds/files.h"
#include "host/time_bound_logger.h"
#include "snapshots/filenames.h"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>

namespace fs = std::filesystem;

namespace snapshots
{
  class SnapshotManager
  {
  private:
    const fs::path snapshot_dir;
    const std::optional<fs::path> read_snapshot_dir = std::nullopt;

  public:
    SnapshotManager(
      const std::string& snapshot_dir_,
      [[maybe_unused]] ringbuffer::AbstractWriterFactory& writer_factory,
      const std::optional<std::string>& read_snapshot_dir_ = std::nullopt) :
      snapshot_dir(snapshot_dir_),
      read_snapshot_dir(read_snapshot_dir_)
    {
      if (fs::is_directory(snapshot_dir))
      {
        LOG_INFO_FMT(
          "Snapshots will be stored in existing directory: {}", snapshot_dir);
      }
      else
      {
        asynchost::TimeBoundLogger log_if_slow(fmt::format(
          "Creating snapshot directory - create_directory({})", snapshot_dir));
        if (!fs::create_directory(snapshot_dir))
        {
          throw std::logic_error(fmt::format(
            "Could not create snapshot directory: {}", snapshot_dir));
        }
      }

      if (
        read_snapshot_dir.has_value() &&
        !fs::is_directory(read_snapshot_dir.value()))
      {
        throw std::logic_error(fmt::format(
          "{} read-only snapshot is not a directory",
          read_snapshot_dir.value()));
      }
    }

    SnapshotManager(const SnapshotManager&) = delete;
    SnapshotManager& operator=(const SnapshotManager&) = delete;

    [[nodiscard]] fs::path get_main_directory() const
    {
      return snapshot_dir;
    }

#define THROW_ON_ERROR(x, name) \
  do \
  { \
    auto rc = x; \
    if (rc == -1) \
    { \
      throw std::runtime_error( \
        fmt::format(/* NOLINTNEXTLINE(concurrency-mt-unsafe) */ \
                    "Error ({}) writing snapshot {} in " #x, \
                    strerror(errno), \
                    name)); \
    } \
  } while (0)

    struct AsyncSnapshotSyncAndRename
    {
      // Inputs, populated at construction
      const std::filesystem::path dir;
      const std::string tmp_file_name;
      const int snapshot_fd;

      // Outputs, populated by callback
      std::string committed_file_name;
    };

    static void on_snapshot_sync_and_rename(uv_work_t* req)
    {
      auto* data = static_cast<AsyncSnapshotSyncAndRename*>(req->data);

      {
        asynchost::TimeBoundLogger log_if_slow(
          fmt::format("Committing snapshot - fsync({})", data->tmp_file_name));
        fsync(data->snapshot_fd); // NOLINT(concurrency-mt-unsafe)
      }

      {
        asynchost::TimeBoundLogger log_if_slow(fmt::format(
          "Closing snapshot file - close({})", data->tmp_file_name));
        close(data->snapshot_fd); // NOLINT(concurrency-mt-unsafe)
      }

      // e.g. snapshot_100_105.committed
      data->committed_file_name =
        fmt::format("{}{}", data->tmp_file_name, snapshot_committed_suffix);
      const auto full_committed_path = data->dir / data->committed_file_name;

      const auto full_tmp_path = data->dir / data->tmp_file_name;
      {
        asynchost::TimeBoundLogger log_if_slow(fmt::format(
          "Renaming snapshot to committed - rename({})", data->tmp_file_name));
        files::rename(full_tmp_path, full_committed_path);
      }
    }

    static void on_snapshot_sync_and_rename_complete(
      uv_work_t* req, int /*status*/)
    {
      auto* data = static_cast<AsyncSnapshotSyncAndRename*>(req->data);

      LOG_INFO_FMT(
        "Renamed temporary snapshot {} to {}",
        data->tmp_file_name,
        data->committed_file_name);

      delete data; // NOLINT(cppcoreguidelines-owning-memory)
      delete req; // NOLINT(cppcoreguidelines-owning-memory)
    }

    void commit_snapshot(
      ::consensus::Index snapshot_idx,
      ::consensus::Index evidence_idx,
      const uint8_t* snapshot_data,
      size_t snapshot_size,
      const uint8_t* receipt_data,
      size_t receipt_size)
    {
      asynchost::TimeBoundLogger log_if_slow(
        fmt::format("Committing snapshot - snapshot_idx={}", snapshot_idx));

      try
      {
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
        {
          asynchost::TimeBoundLogger log_open_if_slow(
            fmt::format("Opening snapshot file - open({})", file_name));
          snapshot_fd =
            files::open_fd(full_snapshot_path, O_CREAT | O_EXCL | O_WRONLY);
        }
        if (snapshot_fd == -1)
        {
          if (errno == EEXIST)
          {
            // In the case that a file with this name already exists, keep
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

        {
          asynchost::TimeBoundLogger log_write_if_slow(fmt::format(
            "Writing snapshot data ({} bytes) - write({})",
            snapshot_size,
            file_name));
          // NOLINTNEXTLINE(concurrency-mt-unsafe)
          THROW_ON_ERROR(
            write(snapshot_fd, snapshot_data, snapshot_size), file_name);
        }
        {
          asynchost::TimeBoundLogger log_write_if_slow(fmt::format(
            "Writing snapshot receipt ({} bytes) - write({})",
            receipt_size,
            file_name));
          // NOLINTNEXTLINE(concurrency-mt-unsafe)
          THROW_ON_ERROR(
            write(snapshot_fd, receipt_data, receipt_size), file_name);
        }

        LOG_INFO_FMT(
          "New snapshot file written to {} [{} bytes] (unsynced)",
          file_name,
          snapshot_size + receipt_size);

        // Call fsync and rename on a worker-thread via uv async, as they
        // may be slow
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        auto* work_handle = new uv_work_t;

        {
          // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
          auto* data = new AsyncSnapshotSyncAndRename{
            .dir = snapshot_dir,
            .tmp_file_name = file_name,
            .snapshot_fd = snapshot_fd,
            .committed_file_name = {}};

          work_handle->data = data;
        }

#ifdef TEST_MODE_EXECUTE_SYNC_INLINE
        on_snapshot_sync_and_rename(work_handle);
        on_snapshot_sync_and_rename_complete(work_handle, 0);
#else
        uv_queue_work(
          uv_default_loop(),
          work_handle,
          &on_snapshot_sync_and_rename,
          &on_snapshot_sync_and_rename_complete);
#endif
      }
      catch (std::exception& e)
      {
        LOG_FAIL_FMT(
          "Exception while attempting to commit snapshot at {}: {}",
          snapshot_idx,
          e.what());
      }
    }
#undef THROW_ON_ERROR

    std::optional<fs::path> find_latest_committed_snapshot()
    {
      std::vector<fs::path> directories;
      directories.push_back(snapshot_dir);
      if (read_snapshot_dir.has_value())
      {
        directories.push_back(read_snapshot_dir.value());
      }
      return find_latest_committed_snapshot_in_directories(directories);
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        ::consensus::snapshot_commit,
        [this](const uint8_t* data, size_t size) {
          const auto [snapshot_idx, evidence_idx, snapshot, receipt] =
            ringbuffer::read_message<::consensus::snapshot_commit>(data, size);
          commit_snapshot(
            snapshot_idx,
            evidence_idx,
            snapshot.data(),
            snapshot.size(),
            receipt.data(),
            receipt.size());
        });
    }
  };
}
