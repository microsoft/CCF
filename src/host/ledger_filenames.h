// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <filesystem>
#include <fmt/format.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace asynchost
{
  namespace fs = std::filesystem;

  static constexpr auto ledger_committed_suffix = ".committed";
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
      is_ledger_file_name_ignored(file_name);
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
    return remove_suffix(
      file_name, ledger_recovery_file_suffix);
  }
}
