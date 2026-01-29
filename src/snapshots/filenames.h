// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace snapshots
{
  namespace fs = std::filesystem;

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
    const auto* end_ptr = str.data() + str.size();

    auto res = std::from_chars(str.data(), end_ptr, idx);
    if (res.ec != std::errc())
    {
      throw std::logic_error(
        fmt::format("Could not read idx from string \"{}\": {}", str, res.ec));
    }

    if (res.ptr != end_ptr)
    {
      throw std::logic_error(fmt::format(
        R"(Trailing characters in "{}" cannot be converted to idx: "{}")",
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

  inline std::vector<std::pair<size_t, fs::path>>
  find_committed_snapshots_in_directories(
    const std::vector<fs::path>& directories,
    std::optional<size_t> minimum_idx = std::nullopt)
  {
    std::vector<std::pair<size_t, fs::path>> committed_snapshots_with_idx;

    for (const auto& dir : directories)
    {
      for (const auto& f : fs::directory_iterator(dir))
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

        const auto idx = get_snapshot_idx_from_file_name(file_name.string());
        if (minimum_idx.has_value() && idx < minimum_idx.value())
        {
          LOG_INFO_FMT(
            "Ignoring snapshot file {} below minimum idx {}",
            file_name,
            minimum_idx.value());
        }
        else
        {
          // Insert snapshot with index, sorted by descending snapshot index
          auto it = std::lower_bound(
            committed_snapshots_with_idx.begin(),
            committed_snapshots_with_idx.end(),
            idx,
            [](const std::pair<size_t, fs::path>& lhs, size_t rhs) {
              return rhs < lhs.first;
            });
          committed_snapshots_with_idx.insert(
            it, std::make_pair(idx, f.path()));
        }
      }
    }

    return committed_snapshots_with_idx;
  }

  inline std::optional<fs::path> find_latest_committed_snapshot_in_directories(
    const std::vector<fs::path>& directories,
    std::optional<size_t> minimum_idx = std::nullopt)
  {
    const auto paths =
      find_committed_snapshots_in_directories(directories, minimum_idx);
    if (paths.empty())
    {
      return std::nullopt;
    }

    return paths.front().second;
  }

  inline std::optional<fs::path> find_latest_committed_snapshot_in_directory(
    const fs::path& directory, std::optional<size_t> minimum_idx = std::nullopt)
  {
    std::vector<fs::path> directories{directory};
    return find_latest_committed_snapshot_in_directories(
      directories, minimum_idx);
  }
}