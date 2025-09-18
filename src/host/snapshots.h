// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/nonstd.h"
#include "consensus/ledger_enclave_types.h"
#include "ds/files.h"
#include "time_bound_logger.h"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>

namespace fs = std::filesystem;

namespace asynchost
{
  static constexpr auto snapshot_file_prefix = "snapshot";
  static constexpr auto snapshot_idx_delimiter = "_";
  static constexpr auto snapshot_committed_suffix = ".committed";

  static bool is_snapshot_file(const std::string& file_name)
  {
    return file_name.starts_with(snapshot_file_prefix);
  }

  static bool is_snapshot_file_committed(const std::string& file_name)
  {
    return file_name.find(snapshot_committed_suffix) != std::string::npos;
  }

  static size_t read_idx(const std::string& str)
  {
    size_t idx = 0;
    auto end_ptr = str.data() + str.size();

    auto res = std::from_chars(str.data(), end_ptr, idx);
    if (res.ec != std::errc())
    {
      throw std::logic_error(
        fmt::format("Could not read idx from string \"{}\": {}", str, res.ec));
    }
    else if (res.ptr != end_ptr)
    {
      throw std::logic_error(fmt::format(
        "Trailing characters in \"{}\" cannot be converted to idx: \"{}\"",
        str,
        std::string(res.ptr, end_ptr)));
    }
    return idx;
  }

  static std::optional<size_t> get_evidence_commit_idx_from_file_name(
    const std::string& file_name)
  {
    // Only returns an evidence commit index for 1.x committed snapshots.
    // 1.x committed snapshots file names are of the form:
    // "snapshot_X_Y.committed_Z" while 2.x+ ones are of the form:
    // "snapshot_X_Y.committed"
    auto pos = file_name.find(snapshot_committed_suffix);
    if (pos == std::string::npos)
    {
      throw std::logic_error(
        fmt::format("Snapshot file \"{}\" is not committed", file_name));
    }

    pos = file_name.find(snapshot_idx_delimiter, pos);
    if (pos == std::string::npos)
    {
      // 2.x+ snapshot
      return std::nullopt;
    }

    return read_idx(file_name.substr(pos + 1));
  }

  static size_t get_snapshot_idx_from_file_name(const std::string& file_name)
  {
    if (!is_snapshot_file(file_name))
    {
      throw std::logic_error(
        fmt::format("File \"{}\" is not a valid snapshot file", file_name));
    }

    auto idx_pos = file_name.find_first_of(snapshot_idx_delimiter);
    if (idx_pos == std::string::npos)
    {
      throw std::logic_error(fmt::format(
        "Snapshot file name {} does not contain snapshot seqno", file_name));
    }

    auto evidence_idx_pos =
      file_name.find_first_of(snapshot_idx_delimiter, idx_pos + 1);
    if (evidence_idx_pos == std::string::npos)
    {
      throw std::logic_error(fmt::format(
        "Snapshot file \"{}\" does not contain evidence index", file_name));
    }

    return read_idx(
      file_name.substr(idx_pos + 1, evidence_idx_pos - idx_pos - 1));
  }

  static size_t get_snapshot_evidence_idx_from_file_name(
    const std::string& file_name)
  {
    if (!is_snapshot_file(file_name))
    {
      throw std::logic_error(
        fmt::format("File \"{}\" is not a valid snapshot file", file_name));
    }

    auto idx_pos = file_name.find_first_of(snapshot_idx_delimiter);
    if (idx_pos == std::string::npos)
    {
      throw std::logic_error(
        fmt::format("Snapshot file \"{}\" does not contain index", file_name));
    }

    auto evidence_idx_pos =
      file_name.find_first_of(snapshot_idx_delimiter, idx_pos + 1);
    if (evidence_idx_pos == std::string::npos)
    {
      throw std::logic_error(fmt::format(
        "Snapshot file \"{}\" does not contain evidence index", file_name));
    }

    // Note: Snapshot file may not be committed
    size_t end_str = std::string::npos;
    auto commit_suffix_pos =
      file_name.find_first_of(snapshot_committed_suffix, evidence_idx_pos + 1);
    if (commit_suffix_pos != std::string::npos)
    {
      end_str = commit_suffix_pos - evidence_idx_pos - 1;
    }

    return read_idx(file_name.substr(evidence_idx_pos + 1, end_str));
  }

  std::optional<fs::path> find_latest_committed_snapshot_in_directory(
    const fs::path& directory, size_t& latest_committed_snapshot_idx)
  {
    std::optional<fs::path> latest_committed_snapshot_file_name = std::nullopt;

    for (auto& f : fs::directory_iterator(directory))
    {
      auto file_name = f.path().filename();
      if (!is_snapshot_file(file_name))
      {
        LOG_INFO_FMT("Ignoring non-snapshot file {}", file_name);
        continue;
      }

      if (!is_snapshot_file_committed(file_name))
      {
        LOG_INFO_FMT("Ignoring non-committed snapshot file {}", file_name);
        continue;
      }

      if (fs::exists(f.path()) && fs::is_empty(f.path()))
      {
        LOG_INFO_FMT("Ignoring empty snapshot file {}", file_name);
        continue;
      }

      auto snapshot_idx = get_snapshot_idx_from_file_name(file_name);
      if (snapshot_idx > latest_committed_snapshot_idx)
      {
        latest_committed_snapshot_file_name = file_name;
        latest_committed_snapshot_idx = snapshot_idx;
      }
    }

    return latest_committed_snapshot_file_name;
  }

  class SnapshotManager
  {
  private:
    ringbuffer::WriterPtr to_enclave;

    const fs::path snapshot_dir;
    const std::optional<fs::path> read_snapshot_dir = std::nullopt;

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
      const std::optional<std::string>& read_snapshot_dir_ = std::nullopt) :
      to_enclave(writer_factory.create_writer_to_inside()),
      snapshot_dir(snapshot_dir_),
      read_snapshot_dir(read_snapshot_dir_)
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

      if (
        read_snapshot_dir.has_value() &&
        !fs::is_directory(read_snapshot_dir.value()))
      {
        throw std::logic_error(fmt::format(
          "{} read-only snapshot is not a directory",
          read_snapshot_dir.value()));
      }
    }

    fs::path get_main_directory() const
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
      throw std::runtime_error(fmt::format( \
        "Error ({}) writing snapshot {} in " #x, strerror(errno), name)); \
    } \
  } while (0)

    struct AsyncSnapshotSyncAndRename
    {
      // Inputs, populated at construction
      const std::filesystem::path dir;
      const std::string tmp_file_name;
      const int snapshot_fd;

      // Outputs, populated by callback
      std::string committed_file_name = {};
    };

    static void on_snapshot_sync_and_rename(uv_work_t* req)
    {
      auto data = static_cast<AsyncSnapshotSyncAndRename*>(req->data);

      {
        asynchost::TimeBoundLogger log_if_slow(
          fmt::format("Committing snapshot - fsync({})", data->tmp_file_name));
        fsync(data->snapshot_fd);
      }

      close(data->snapshot_fd);

      // e.g. snapshot_100_105.committed
      data->committed_file_name =
        fmt::format("{}{}", data->tmp_file_name, snapshot_committed_suffix);
      const auto full_committed_path = data->dir / data->committed_file_name;

      const auto full_tmp_path = data->dir / data->tmp_file_name;
      files::rename(full_tmp_path, full_committed_path);

      // read and log the hash of the written snapshot
      auto raw = files::slurp(data->committed_file_name);
      LOG_INFO_FMT(
        "Written snapshot to {} (size: {} bytes, sha256: {} )",
        data->committed_file_name,
        raw.size(),
        ccf::crypto::Sha256Hash(raw).hex_str());
    }

    static void on_snapshot_sync_and_rename_complete(uv_work_t* req, int status)
    {
      auto data = static_cast<AsyncSnapshotSyncAndRename*>(req->data);

      LOG_INFO_FMT(
        "Renamed temporary snapshot {} to {}",
        data->tmp_file_name,
        data->committed_file_name);

      delete data;
      delete req;
    }

    void commit_snapshot(
      ::consensus::Index snapshot_idx,
      const uint8_t* receipt_data,
      size_t receipt_size)
    {
      TimeBoundLogger log_if_slow(
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

              THROW_ON_ERROR(
                write(snapshot_fd, snapshot->data(), snapshot->size()),
                file_name);
              THROW_ON_ERROR(
                write(snapshot_fd, receipt_data, receipt_size), file_name);

              LOG_INFO_FMT(
                "New snapshot file written to {} [{} bytes] (unsynced)",
                file_name,
                snapshot->size() + receipt_size);

              // Call fsync and rename on a worker-thread via uv async, as they
              // may be slow
              uv_work_t* work_handle = new uv_work_t;

              {
                auto* data = new AsyncSnapshotSyncAndRename{
                  .dir = snapshot_dir,
                  .tmp_file_name = file_name,
                  .snapshot_fd = snapshot_fd};

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

            auto sha = ccf::crypto::Sha256Hash(it->second.snapshot);
            LOG_INFO_FMT(
              "Writing snapshot to {} (sha256: {})", full_snapshot_path, sha);

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

    std::optional<std::pair<fs::path, fs::path>>
    find_latest_committed_snapshot()
    {
      // Keep track of latest snapshot file in both directories
      size_t latest_idx = 0;

      std::optional<fs::path> read_only_latest_committed_snapshot =
        std::nullopt;
      if (read_snapshot_dir.has_value())
      {
        read_only_latest_committed_snapshot =
          find_latest_committed_snapshot_in_directory(
            read_snapshot_dir.value(), latest_idx);
      }

      auto main_latest_committed_snapshot =
        find_latest_committed_snapshot_in_directory(snapshot_dir, latest_idx);

      if (main_latest_committed_snapshot.has_value())
      {
        return std::make_pair(
          snapshot_dir, main_latest_committed_snapshot.value());
      }
      else if (read_only_latest_committed_snapshot.has_value())
      {
        return std::make_pair(
          read_snapshot_dir.value(),
          read_only_latest_committed_snapshot.value());
      }

      return std::nullopt;
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
