// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "consensus/ledger_enclave_types.h"
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
    ringbuffer::WriterPtr to_enclave;

    const fs::path snapshot_dir;
    const std::optional<fs::path> read_snapshot_dir = std::nullopt;
    const std::optional<size_t> max_retained_snapshot_files = std::nullopt;

    struct CleanupTimerState
    {
      uv_timer_t handle{};
      bool cleanup_pending = false;
      // Back-pointer to owning SnapshotManager. Nulled in destructor
      // (after uv_timer_stop) so in-flight cleanup work items see nullptr
      // rather than a dangling pointer.
      SnapshotManager* owner = nullptr;
    };
    // Heap-allocated so it can outlive this object (uv_close is async).
    // Freed in the uv_close callback.
    CleanupTimerState* cleanup_state = nullptr;

    struct PendingSnapshot
    {
      ::consensus::Index evidence_idx;
      std::shared_ptr<std::vector<uint8_t>> snapshot;
    };
    std::map<size_t, PendingSnapshot> pending_snapshots;

  public:
    SnapshotManager(
      const std::string& snapshot_dir_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      const std::optional<std::string>& read_snapshot_dir_ = std::nullopt,
      const std::optional<size_t>& max_retained_snapshot_files_ = std::nullopt,
      std::chrono::milliseconds cleanup_interval =
        std::chrono::milliseconds::zero()) :
      to_enclave(writer_factory.create_writer_to_inside()),
      snapshot_dir(snapshot_dir_),
      read_snapshot_dir(read_snapshot_dir_),
      max_retained_snapshot_files(max_retained_snapshot_files_)
    {
      if (
        max_retained_snapshot_files.has_value() &&
        max_retained_snapshot_files.value() < 2)
      {
        throw std::logic_error(fmt::format(
          "max_retained_snapshot_files must be at least 2, got {}",
          max_retained_snapshot_files.value()));
      }
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

      if (
        read_snapshot_dir.has_value() &&
        !fs::is_directory(read_snapshot_dir.value()))
      {
        throw std::logic_error(fmt::format(
          "{} read-only snapshot is not a directory",
          read_snapshot_dir.value()));
      }

#ifndef TEST_MODE_EXECUTE_SYNC_INLINE
      if (
        max_retained_snapshot_files.has_value() &&
        cleanup_interval > std::chrono::milliseconds::zero())
      {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        cleanup_state = new CleanupTimerState{};
        cleanup_state->owner = this;
        uv_timer_init(uv_default_loop(), &cleanup_state->handle);
        cleanup_state->handle.data = cleanup_state;
        uv_timer_start(
          &cleanup_state->handle,
          on_cleanup_timer,
          cleanup_interval.count(),
          cleanup_interval.count());
        // Don't let the cleanup timer keep the event loop alive
        uv_unref(reinterpret_cast<uv_handle_t*>(&cleanup_state->handle));
      }
#endif
    }

    ~SnapshotManager()
    {
#ifndef TEST_MODE_EXECUTE_SYNC_INLINE
      if (cleanup_state != nullptr)
      {
        uv_timer_stop(&cleanup_state->handle);
        // Sever back-pointer so any in-flight cleanup work items don't
        // dereference a destroyed SnapshotManager
        cleanup_state->owner = nullptr;
        uv_close(
          reinterpret_cast<uv_handle_t*>(&cleanup_state->handle),
          [](uv_handle_t* h) {
            delete static_cast<CleanupTimerState*>(
              h->data); // NOLINT(cppcoreguidelines-owning-memory)
          });
        cleanup_state = nullptr;
      }
#endif
    }

    SnapshotManager(const SnapshotManager&) = delete;
    SnapshotManager& operator=(const SnapshotManager&) = delete;

    [[nodiscard]] fs::path get_main_directory() const
    {
      return snapshot_dir;
    }

    std::shared_ptr<std::vector<uint8_t>> add_pending_snapshot(
      ::consensus::Index idx,
      ::consensus::Index evidence_idx,
      size_t requested_size)
    {
      auto snapshot = std::make_shared<std::vector<uint8_t>>(requested_size);
      pending_snapshots.emplace(idx, PendingSnapshot{evidence_idx, snapshot});

      LOG_DEBUG_FMT(
        "Added pending snapshot {} [{} bytes]", idx, requested_size);

      return snapshot;
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

    static void cleanup_old_snapshots(const fs::path& dir, size_t max_retained)
    {
      std::vector<fs::path> directories{dir};
      auto committed = find_committed_snapshots_in_directories(directories);

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
          fs::remove(path);
        }
      }
    }

    struct SnapshotCleanupWork
    {
      fs::path dir;
      size_t max_retained;
      CleanupTimerState* state;
    };

    static void on_snapshot_cleanup(uv_work_t* req)
    {
      auto* work = static_cast<SnapshotCleanupWork*>(req->data);
      cleanup_old_snapshots(work->dir, work->max_retained);
    }

    static void on_snapshot_cleanup_complete(uv_work_t* req, int /*status*/)
    {
      auto* work = static_cast<SnapshotCleanupWork*>(req->data);
      LOG_DEBUG_FMT("Snapshot cleanup completed");
#ifndef TEST_MODE_EXECUTE_SYNC_INLINE
      if (work->state != nullptr)
      {
        work->state->cleanup_pending = false;
      }
#endif
      delete work; // NOLINT(cppcoreguidelines-owning-memory)
      delete req; // NOLINT(cppcoreguidelines-owning-memory)
    }

    // Schedule cleanup on the worker thread pool if not already pending.
    // Must be called from the event loop thread.
    void schedule_cleanup(uv_loop_t* loop)
    {
#ifndef TEST_MODE_EXECUTE_SYNC_INLINE
      if (
        !max_retained_snapshot_files.has_value() || cleanup_state == nullptr ||
        cleanup_state->cleanup_pending)
      {
        return;
      }
      cleanup_state->cleanup_pending = true;
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* cleanup_work = new SnapshotCleanupWork{
        .dir = snapshot_dir,
        .max_retained = max_retained_snapshot_files.value(),
        .state = cleanup_state};
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* work_handle = new uv_work_t;
      work_handle->data = cleanup_work;
      uv_queue_work(
        loop, work_handle, &on_snapshot_cleanup, &on_snapshot_cleanup_complete);
#endif
    }

    static void on_cleanup_timer(uv_timer_t* handle)
    {
      auto* state = static_cast<CleanupTimerState*>(handle->data);
      if (state->owner != nullptr)
      {
        state->owner->schedule_cleanup(handle->loop);
      }
    }

    struct AsyncSnapshotSyncAndRename
    {
      // Inputs, populated at construction
      const std::filesystem::path dir;
      const std::string tmp_file_name;
      const int snapshot_fd;
      SnapshotManager* owner;

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

      close(data->snapshot_fd); // NOLINT(concurrency-mt-unsafe)

      // e.g. snapshot_100_105.committed
      data->committed_file_name =
        fmt::format("{}{}", data->tmp_file_name, snapshot_committed_suffix);
      const auto full_committed_path = data->dir / data->committed_file_name;

      const auto full_tmp_path = data->dir / data->tmp_file_name;
      files::rename(full_tmp_path, full_committed_path);
    }

    static void on_snapshot_sync_and_rename_complete(
      uv_work_t* req, int /*status*/)
    {
      auto* data = static_cast<AsyncSnapshotSyncAndRename*>(req->data);

      LOG_INFO_FMT(
        "Renamed temporary snapshot {} to {}",
        data->tmp_file_name,
        data->committed_file_name);

      // Schedule cleanup of old snapshots now that the rename is complete
      if (data->owner != nullptr)
      {
        data->owner->schedule_cleanup(req->loop);
      }

      delete data; // NOLINT(cppcoreguidelines-owning-memory)
      delete req; // NOLINT(cppcoreguidelines-owning-memory)
    }

    void commit_snapshot(
      ::consensus::Index snapshot_idx,
      const uint8_t* receipt_data,
      size_t receipt_size)
    {
      asynchost::TimeBoundLogger log_if_slow(
        fmt::format("Committing snapshot - snapshot_idx={}", snapshot_idx));

      try
      {
        for (auto it = pending_snapshots.begin(); it != pending_snapshots.end();
             it++)
        {
          if (snapshot_idx == it->first)
          {
            // e.g. snapshot_100_105
            auto file_name = fmt::format(
              "{}{}{}{}{}",
              snapshot_file_prefix,
              snapshot_idx_delimiter,
              it->first,
              snapshot_idx_delimiter,
              it->second.evidence_idx);
            auto full_snapshot_path = snapshot_dir / file_name;

            int snapshot_fd = open(
              full_snapshot_path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0664);
            if (snapshot_fd == -1)
            {
              if (errno == EEXIST)
              {
                // In the case that a file with this name already exists, keep
                // existing file and drop pending snapshot
                LOG_FAIL_FMT(
                  "Cannot write snapshot as file already exists: {}",
                  file_name);
              }
              else
              {
                LOG_FAIL_FMT(
                  "Cannot write snapshot: error ({}) opening file {}",
                  errno,
                  file_name);
              }
            }
            else
            {
              const auto& snapshot = it->second.snapshot;

              {
                asynchost::TimeBoundLogger log_write_if_slow(
                  fmt::format("Writing snapshot to {}", file_name));
                // NOLINTNEXTLINE(concurrency-mt-unsafe)
                THROW_ON_ERROR(
                  write(snapshot_fd, snapshot->data(), snapshot->size()),
                  file_name);
                // NOLINTNEXTLINE(concurrency-mt-unsafe)
                THROW_ON_ERROR(
                  write(snapshot_fd, receipt_data, receipt_size), file_name);
              }

              LOG_INFO_FMT(
                "New snapshot file written to {} [{} bytes] (unsynced)",
                file_name,
                snapshot->size() + receipt_size);

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
                  .owner = this,
                  .committed_file_name = {}};

                work_handle->data = data;
              }

#ifdef TEST_MODE_EXECUTE_SYNC_INLINE
              on_snapshot_sync_and_rename(work_handle);
              on_snapshot_sync_and_rename_complete(work_handle, 0);
              // In test mode there is no event loop, so run cleanup
              // synchronously
              if (max_retained_snapshot_files.has_value())
              {
                cleanup_old_snapshots(
                  snapshot_dir, max_retained_snapshot_files.value());
              }
#else
              uv_queue_work(
                uv_default_loop(),
                work_handle,
                &on_snapshot_sync_and_rename,
                &on_snapshot_sync_and_rename_complete);
#endif
            }

            pending_snapshots.erase(it);

            return;
          }
        }

        LOG_FAIL_FMT("Could not find snapshot to commit at {}", snapshot_idx);
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
        ::consensus::snapshot_allocate,
        [this](const uint8_t* data, size_t size) {
          auto idx = serialized::read<::consensus::Index>(data, size);
          auto evidence_idx = serialized::read<::consensus::Index>(data, size);
          auto requested_size = serialized::read<size_t>(data, size);
          auto generation_count = serialized::read<uint32_t>(data, size);

          auto snapshot =
            add_pending_snapshot(idx, evidence_idx, requested_size);

          RINGBUFFER_WRITE_MESSAGE(
            ::consensus::snapshot_allocated,
            to_enclave,
            std::span<uint8_t>{snapshot->data(), snapshot->size()},
            generation_count);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        ::consensus::snapshot_commit,
        [this](const uint8_t* data, size_t size) {
          auto snapshot_idx = serialized::read<::consensus::Index>(data, size);
          commit_snapshot(snapshot_idx, data, size);
        });
    }
  };
}
