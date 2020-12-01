// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "host/ledger.h"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>

namespace fs = std::filesystem;

namespace asynchost
{
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
      auto pos = file_name.find(snapshot_idx_delimiter);
      if (pos == std::string::npos)
      {
        throw std::logic_error(fmt::format(
          "Snapshot file name {} does not contain seqno", file_name));
      }

      return std::stol(file_name.substr(pos + 1));
    }

    std::optional<std::pair<size_t, size_t>>
    get_snapshot_evidence_idx_from_file_name(const std::string& file_name)
    {
      auto pos = file_name.find(
        fmt::format("{}{}", snapshot_committed_suffix, snapshot_idx_delimiter));
      if (pos == std::string::npos)
      {
        // Snapshot is not yet committed
        return std::nullopt;
      }

      auto committed_suffix = file_name.substr(pos);
      auto committed_separator_pos =
        committed_suffix.find(snapshot_idx_delimiter);
      if (committed_separator_pos == std::string::npos)
      {
        // Committed snapshot does not contain committed indices separator
        return std::nullopt;
      }

      auto evidence_indices =
        committed_suffix.substr(committed_separator_pos + 1);
      auto evidence_indices_separator_pos =
        evidence_indices.find(snapshot_idx_delimiter);
      if (evidence_indices_separator_pos == std::string::npos)
      {
        // Committed snapshot does not contain evidence indices separator
        return std::nullopt;
      }

      size_t evidence_idx;
      std::string_view str_evidence_idx =
        evidence_indices.substr(0, evidence_indices_separator_pos);
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
      std::string_view str_evidence_commit_idx =
        evidence_indices.substr(evidence_indices_separator_pos + 1);
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

    void write_snapshot(
      consensus::Index idx, const uint8_t* snapshot_data, size_t snapshot_size)
    {
      auto snapshot_file_name = fmt::format(
        "{}{}{}", snapshot_file_prefix, snapshot_idx_delimiter, idx);
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
      consensus::Index snapshot_idx,
      consensus::Index evidence_idx,
      consensus::Index evidence_commit_idx)
    {
      // Find previously-generated snapshot for snapshot_idx and rename file,
      // including evidence_idx and evidence_commit_idx in name too
      for (auto const& f : fs::directory_iterator(snapshot_dir))
      {
        auto file_name = f.path().filename().string();
        if (
          !get_snapshot_evidence_idx_from_file_name(file_name).has_value() &&
          get_snapshot_idx_from_file_name(file_name) == snapshot_idx)
        {
          LOG_INFO_FMT(
            "Committing snapshot file \"{}\" with evidence at {} and evidence "
            "proof committed at {}",
            file_name,
            evidence_idx,
            evidence_commit_idx);

          const auto committed_file_name = fmt::format(
            "{}.{}{}{}{}{}",
            file_name,
            snapshot_committed_suffix,
            snapshot_idx_delimiter,
            evidence_idx,
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
          snapshot_file = f.path().string();
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
          write_snapshot(idx, data, size);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::snapshot_commit,
        [this](const uint8_t* data, size_t size) {
          auto snapshot_idx = serialized::read<consensus::Index>(data, size);
          auto evidence_idx = serialized::read<consensus::Index>(data, size);
          auto evidence_commit_idx =
            serialized::read<consensus::Index>(data, size);
          commit_snapshot(snapshot_idx, evidence_idx, evidence_commit_idx);
        });
    }
  };
}
