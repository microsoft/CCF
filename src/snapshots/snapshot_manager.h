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
            // e.g. snapshot_100_105.committed
            auto file_name = fmt::format(
              "{}{}{}{}{}{}",
              snapshot_file_prefix,
              snapshot_idx_delimiter,
              it->first,
              snapshot_idx_delimiter,
              it->second.evidence_idx,
              snapshot_committed_suffix);
            auto full_snapshot_path = snapshot_dir / file_name;

            if (fs::exists(full_snapshot_path))
            {
              // In the case that a file with this name already exists, keep
              // existing file and drop pending snapshot
              LOG_FAIL_FMT(
                "Cannot write snapshot as file already exists: {}", file_name);
            }
            else
            {
              std::ofstream snapshot_file(
                full_snapshot_path, std::ios::app | std::ios::binary);
              if (!snapshot_file.good())
              {
                LOG_FAIL_FMT(
                  "Cannot write snapshot: error opening file {}", file_name);
              }
              else
              {
                const auto& snapshot = it->second.snapshot;
                snapshot_file.write(
                  reinterpret_cast<const char*>(snapshot->data()),
                  snapshot->size());
                snapshot_file.write(
                  reinterpret_cast<const char*>(receipt_data), receipt_size);

                LOG_INFO_FMT(
                  "New snapshot file written to {} [{} bytes]",
                  file_name,
                  static_cast<size_t>(snapshot_file.tellp()));
              }
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
