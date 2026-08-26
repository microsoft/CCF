// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <charconv>
#include <filesystem>
#include <fmt/format.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace asynchost
{
  namespace fs = std::filesystem;

  static constexpr auto ledger_committed_suffix = ".committed";
  static constexpr auto ledger_committed_prefix_suffix = ".committed_prefix";
  static constexpr auto ledger_start_idx_delimiter = "_";
  static constexpr auto ledger_last_idx_delimiter = "-";
  static constexpr auto ledger_recovery_file_suffix = ".recovery";
  static constexpr auto ledger_ignored_file_suffix = ".ignored";

  static inline size_t get_start_idx_from_file_name(
    const std::string& file_name)
  {
    auto pos = file_name.find(ledger_start_idx_delimiter);
    if (pos == std::string::npos)
    {
      throw std::logic_error(fmt::format(
        "Ledger file name {} does not contain a start seqno", file_name));
    }

    return std::stoull(file_name.substr(pos + 1));
  }

  static inline std::optional<size_t> get_last_idx_from_file_name(
    const std::string& file_name)
  {
    auto pos = file_name.find(ledger_last_idx_delimiter);
    if (pos == std::string::npos)
    {
      // Non-committed file names do not contain a last idx
      return std::nullopt;
    }

    return std::stoull(file_name.substr(pos + 1));
  }

  static inline bool is_ledger_file_name_committed(const std::string& file_name)
  {
    return file_name.ends_with(ledger_committed_suffix);
  }

  static inline bool is_ledger_file_name_committed_prefix(
    const std::string& file_name)
  {
    return file_name.ends_with(ledger_committed_prefix_suffix);
  }

  static inline std::optional<std::pair<size_t, size_t>>
  get_ledger_committed_prefix_range_from_file_name(std::string_view file_name)
  {
    static constexpr std::string_view prefix = "ledger_";
    static constexpr std::string_view suffix = ledger_committed_prefix_suffix;

    if (!file_name.starts_with(prefix) || !file_name.ends_with(suffix))
    {
      return std::nullopt;
    }

    file_name.remove_prefix(prefix.size());
    file_name.remove_suffix(suffix.size());

    const auto delimiter = file_name.find(ledger_last_idx_delimiter);
    if (
      delimiter == std::string_view::npos || delimiter == 0 ||
      delimiter == file_name.size() - 1 ||
      file_name.find(ledger_last_idx_delimiter, delimiter + 1) !=
        std::string_view::npos)
    {
      return std::nullopt;
    }

    const auto parse_idx = [](std::string_view value) -> std::optional<size_t> {
      size_t idx = 0;
      const auto* const end = value.data() + value.size();
      const auto [ptr, ec] = std::from_chars(value.data(), end, idx);
      if (ec != std::errc() || ptr != end)
      {
        return std::nullopt;
      }
      return idx;
    };

    const auto start_idx = parse_idx(file_name.substr(0, delimiter));
    const auto end_idx = parse_idx(file_name.substr(delimiter + 1));
    if (
      !start_idx.has_value() || !end_idx.has_value() ||
      start_idx.value() == 0 || end_idx.value() < start_idx.value())
    {
      return std::nullopt;
    }

    return std::make_pair(start_idx.value(), end_idx.value());
  }

  static inline bool is_ledger_file_name_recovery(const std::string& file_name)
  {
    return file_name.ends_with(ledger_recovery_file_suffix);
  }

  static inline bool is_ledger_file_name_ignored(const std::string& file_name)
  {
    return file_name.ends_with(ledger_ignored_file_suffix);
  }

  static inline bool is_ledger_file_ignored(const std::string& file_name)
  {
    // Catch-all for all files that should be ignored
    return is_ledger_file_name_recovery(file_name) ||
      is_ledger_file_name_ignored(file_name) ||
      is_ledger_file_name_committed_prefix(file_name);
  }

  static inline fs::path remove_suffix(
    std::string_view file_name, const std::string& suffix)
  {
    if (file_name.ends_with(suffix))
    {
      file_name.remove_suffix(suffix.size());
    }
    return file_name;
  }

  static inline fs::path remove_recovery_suffix(std::string_view file_name)
  {
    return remove_suffix(file_name, ledger_recovery_file_suffix);
  }
}
