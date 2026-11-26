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

  static inline std::optional<std::pair<size_t, size_t>>
  parse_canonical_ledger_range(
    std::string_view file_name, std::string_view suffix)
  {
    static constexpr std::string_view prefix = "ledger_";
    if (
      file_name.size() < prefix.size() + suffix.size() ||
      !file_name.starts_with(prefix) || !file_name.ends_with(suffix))
    {
      return std::nullopt;
    }

    const auto body = file_name.substr(
      prefix.size(), file_name.size() - prefix.size() - suffix.size());

    const auto parse_positive_canonical =
      [](std::string_view s, size_t& out) -> const char* {
      if (s.empty() || s.front() < '1' || s.front() > '9')
      {
        return nullptr;
      }
      const auto result = std::from_chars(s.data(), s.data() + s.size(), out);
      if (result.ec != std::errc())
      {
        return nullptr;
      }
      return result.ptr;
    };

    size_t start_idx = 0;
    const auto* sep = parse_positive_canonical(body, start_idx);
    if (
      sep == nullptr || sep == body.data() + body.size() ||
      *sep != ledger_last_idx_delimiter[0])
    {
      return std::nullopt;
    }

    const auto rest = body.substr(static_cast<size_t>(sep - body.data()) + 1);
    size_t end_idx = 0;
    const auto* end = parse_positive_canonical(rest, end_idx);
    if (
      end == nullptr || end != rest.data() + rest.size() || end_idx < start_idx)
    {
      return std::nullopt;
    }

    return std::pair{start_idx, end_idx};
  }

  static inline std::optional<std::pair<size_t, size_t>>
  get_ledger_committed_range_from_file_name(
    std::string_view file_name, bool allow_recovery = false)
  {
    if (allow_recovery && file_name.ends_with(ledger_recovery_file_suffix))
    {
      file_name.remove_suffix(
        std::string_view(ledger_recovery_file_suffix).size());
    }
    return parse_canonical_ledger_range(file_name, ledger_committed_suffix);
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
    const auto range =
      parse_canonical_ledger_range(file_name, ledger_committed_prefix_suffix);
    if (!range.has_value())
    {
      return std::nullopt;
    }

    return CommittedLedgerPrefixRange{
      .start_idx = range->first, .end_idx = range->second};
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
