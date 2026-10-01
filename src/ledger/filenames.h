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

namespace ccf::ledger
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

  // Inclusive range of sequence numbers covered by a committed ledger prefix
  struct CommittedLedgerPrefixRange
  {
    size_t start_idx;
    size_t end_idx;
  };

  static inline std::string get_ledger_committed_prefix_file_name(
    const CommittedLedgerPrefixRange& range)
  {
    return fmt::format(
      "ledger{}{}{}{}{}",
      ledger_start_idx_delimiter,
      range.start_idx,
      ledger_last_idx_delimiter,
      range.end_idx,
      ledger_committed_prefix_suffix);
  }

  static inline std::optional<CommittedLedgerPrefixRange>
  get_ledger_committed_prefix_range_from_file_name(std::string_view file_name)
  {
    const auto start_pos = file_name.find(ledger_start_idx_delimiter);
    const auto end_pos = file_name.find(ledger_last_idx_delimiter);
    if (
      start_pos == std::string_view::npos ||
      end_pos == std::string_view::npos || end_pos < start_pos)
    {
      return std::nullopt;
    }

    const auto parse_idx_after = [&](size_t pos) -> std::optional<size_t> {
      size_t idx = 0;
      const auto result = std::from_chars(
        file_name.data() + pos + 1, file_name.data() + file_name.size(), idx);
      if (result.ec != std::errc())
      {
        return std::nullopt;
      }
      return idx;
    };

    const auto start_idx = parse_idx_after(start_pos);
    const auto end_idx = parse_idx_after(end_pos);
    if (
      !start_idx.has_value() || !end_idx.has_value() ||
      start_idx.value() == 0 || end_idx.value() < start_idx.value())
    {
      return std::nullopt;
    }

    // Only the exact name produced for a range is accepted, so that each
    // committed prefix has a single, canonical name
    const CommittedLedgerPrefixRange range{
      .start_idx = start_idx.value(), .end_idx = end_idx.value()};
    if (get_ledger_committed_prefix_file_name(range) != file_name)
    {
      return std::nullopt;
    }

    return range;
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
