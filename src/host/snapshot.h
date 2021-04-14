// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/files.h"
#include "host/ledger.h"

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
  static constexpr auto snapshot_committed_suffix = "committed";

  std::optional<std::pair<size_t, size_t>>
  get_snapshot_evidence_idx_from_file_name(const std::string& file_name)
  {
    // Returns snapshot evidence and evidence commit proof indices
    auto commit_pos =
      file_name.find(fmt::format(".{}", snapshot_committed_suffix));
    if (commit_pos == std::string::npos)
    {
      // Snapshot is not yet committed
      return std::nullopt;
    }

    auto idx_pos = file_name.find_first_of(snapshot_idx_delimiter);
    if (idx_pos == std::string::npos)
    {
      // Snapshot has no idx
      return std::nullopt;
    }

    auto evidence_pos =
      file_name.find_first_of(snapshot_idx_delimiter, idx_pos + 1);
    if (evidence_pos == std::string::npos)
    {
      // Snapshot has no evidence idx
      return std::nullopt;
    }

    auto evidence_proof_pos = file_name.find_last_of(snapshot_idx_delimiter);
    if (evidence_proof_pos == std::string::npos)
    {
      // Snapshot has no evidence proof idx
      return std::nullopt;
    }

    size_t evidence_idx;
    const auto evidence_start = evidence_pos + 1;
    const auto str_evidence_idx =
      file_name.substr(evidence_start, commit_pos - evidence_start);
    if (
      std::from_chars(
        str_evidence_idx.data(),
        str_evidence_idx.data() + str_evidence_idx.size(),
        evidence_idx)
        .ec != std::errc())
    {
      return std::nullopt;
    }

    size_t evidence_commit_idx;
    const auto str_evidence_commit_idx =
      file_name.substr(evidence_proof_pos + 1);
    if (
      std::from_chars(
        str_evidence_commit_idx.data(),
        str_evidence_commit_idx.data() + str_evidence_commit_idx.size(),
        evidence_commit_idx)
        .ec != std::errc())
    {
      return std::nullopt;
    }

    return std::make_pair(evidence_idx, evidence_commit_idx);
  }

  class SnapshotManager
  {
  private:
    const std::string snapshot_dir;
    const Ledger& ledger;

    static constexpr auto snapshot_file_prefix = "snapshot";
    static constexpr auto snapshot_idx_delimiter = "_";
    static constexpr auto snapshot_committed_suffix = "committed";

    size_t get_snapshot_idx_from_file_name(const std::string& file_name)
    {
      // Assumes snapshot file is not committed
      auto pos = file_name.find(snapshot_idx_delimiter);
      if (pos == std::string::npos)
      {
        throw std::logic_error(fmt::format(
          "Snapshot file name {} does not contain seqno", file_name));
      }

      return std::stol(file_name.substr(pos + 1));
    }

  public:
    SnapshotManager(const std::string& snapshot_dir_, const Ledger& ledger_) :
      snapshot_dir(snapshot_dir_),
      ledger(ledger_)
    {
      if (fs::is_directory(snapshot_dir))
      {
        LOG_INFO_FMT(
          "Snapshots will be stored in existing directory: {}", snapshot_dir);
      }
      else if (!fs::create_directory(snapshot_dir))
      {
        throw std::logic_error(fmt::format(
          "Error: Could not create snapshot directory: {}", snapshot_dir));
      }
    }

    std::vector<uint8_t> read_snapshot(const std::string& file_name)
    {
      return files::slurp(fs::path(snapshot_dir) / fs::path(file_name));
    }

    void write_snapshot(
      consensus::Index idx,
      consensus::Index evidence_idx,
      const uint8_t* snapshot_data,
      size_t snapshot_size)
    {
      auto snapshot_file_name = fmt::format(
        "{}{}{}{}{}",
        snapshot_file_prefix,
        snapshot_idx_delimiter,
        idx,
        snapshot_idx_delimiter,
        evidence_idx);
      auto full_snapshot_path =
        fs::path(snapshot_dir) / fs::path(snapshot_file_name);

      if (fs::exists(full_snapshot_path))
      {
        throw std::logic_error(fmt::format(
          "Cannot write snapshot at {} since file already exists: {}",
          idx,
          full_snapshot_path));
      }

      LOG_INFO_FMT(
        "Writing new snapshot to {} [{}]", snapshot_file_name, snapshot_size);

      std::ofstream snapshot_file(
        full_snapshot_path, std::ios::out | std::ios::binary);
      snapshot_file.write(
        reinterpret_cast<const char*>(snapshot_data), snapshot_size);
    }

    void commit_snapshot(
      consensus::Index snapshot_idx, consensus::Index evidence_commit_idx)
    {
      try
      {
        // Find previously-generated snapshot for snapshot_idx and rename file,
        // including evidence_commit_idx in name too
        for (auto const& f : fs::directory_iterator(snapshot_dir))
        {
          auto file_name = f.path().filename().string();
          if (
            !get_snapshot_evidence_idx_from_file_name(file_name).has_value() &&
            get_snapshot_idx_from_file_name(file_name) == snapshot_idx)
          {
            LOG_INFO_FMT(
              "Committing snapshot file \"{}\" with evidence proof committed "
              "at "
              "{}",
              file_name,
              evidence_commit_idx);

            const auto committed_file_name = fmt::format(
              "{}.{}{}{}",
              file_name,
              snapshot_committed_suffix,
              snapshot_idx_delimiter,
              evidence_commit_idx);

            fs::rename(
              fs::path(snapshot_dir) / fs::path(file_name),
              fs::path(snapshot_dir) / fs::path(committed_file_name));

            return;
          }
        }

        LOG_FAIL_FMT("Could not find snapshot to commit at {}", snapshot_idx);
      }
      catch (std::exception& e)
      {
        LOG_FAIL_FMT(
          "Exception while attempting to commit snapshot: {}", e.what());
      }
    }

    std::optional<std::string> find_latest_committed_snapshot()
    {
      std::optional<std::string> snapshot_file = std::nullopt;
      size_t latest_idx = 0;

      size_t ledger_last_idx = ledger.get_last_idx();

      for (auto& f : fs::directory_iterator(snapshot_dir))
      {
        auto file_name = f.path().filename().string();
        if (
          file_name.find(fmt::format(
            "{}{}", snapshot_file_prefix, snapshot_idx_delimiter)) ==
          std::string::npos)
        {
          LOG_INFO_FMT("Ignoring non-snapshot file \"{}\"", file_name);
          continue;
        }

        auto evidence_indices =
          get_snapshot_evidence_idx_from_file_name(file_name);
        if (!evidence_indices.has_value())
        {
          LOG_INFO_FMT("Ignoring uncommitted snapshot file \"{}\"", file_name);
          continue;
        }

        if (evidence_indices->second > ledger.get_last_idx())
        {
          LOG_INFO_FMT(
            "Ignoring \"{}\" because ledger does not contain evidence commit "
            "seqno: evidence commit seqno {} > last ledger seqno {}",
            file_name,
            evidence_indices->second,
            ledger_last_idx);
          continue;
        }

        auto pos = file_name.find(snapshot_idx_delimiter);
        size_t snapshot_idx = std::stol(file_name.substr(pos + 1));
        if (snapshot_idx > latest_idx)
        {
          snapshot_file = file_name;
          latest_idx = snapshot_idx;
        }
      }

      return snapshot_file;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, consensus::snapshot, [this](const uint8_t* data, size_t size) {
          auto idx = serialized::read<consensus::Index>(data, size);
          auto evidence_idx = serialized::read<consensus::Index>(data, size);
          write_snapshot(idx, evidence_idx, data, size);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::snapshot_commit,
        [this](const uint8_t* data, size_t size) {
          auto snapshot_idx = serialized::read<consensus::Index>(data, size);
          auto evidence_commit_idx =
            serialized::read<consensus::Index>(data, size);
          commit_snapshot(snapshot_idx, evidence_commit_idx);
        });
    }
  };
}
