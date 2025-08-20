// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"

#define FMT_HEADER_ONLY
#include <charconv>
#include <fmt/format.h>
#include <map>
#include <optional>
#include <string_view>

namespace ccf::http
{
  // Query is parsed into a multimap, so that duplicate keys are retained.
  // Handling of duplicates (or ignoring them entirely) is left to the caller.
  // Keys and values are URL-decoded strings.
  using ParsedQuery = std::multimap<std::string, std::string>;

  ParsedQuery parse_query(const std::string_view& query);

  template <typename T>
  static bool get_query_value(
    const ParsedQuery& pq,
    const std::string_view& param_key,
    T& val,
    std::string& error_reason)
  {
    // Convert string_view to string for map lookup
    std::string key_str(param_key);
    const auto it = pq.find(key_str);

    if (it == pq.end())
    {
      error_reason = fmt::format("Missing query parameter '{}'", param_key);
      return false;
    }

    const std::string& param_val = it->second;

    if constexpr (std::is_same_v<T, std::string>)
    {
      val = param_val;
      return true;
    }
    else if constexpr (std::is_same_v<T, bool>)
    {
      if (param_val == "true")
      {
        val = true;
        return true;
      }
      else if (param_val == "false")
      {
        val = false;
        return true;
      }
      else
      {
        error_reason = fmt::format(
          "Unable to parse value '{}' as bool in parameter '{}'",
          param_val,
          param_key);
        return false;
      }
    }
    else if constexpr (std::is_integral_v<T>)
    {
      const auto [p, ec] = std::from_chars(
        param_val.data(), param_val.data() + param_val.size(), val);
      if (ec != std::errc() || p != param_val.data() + param_val.size())
      {
        error_reason = fmt::format(
          "Unable to parse value '{}' in parameter '{}'", param_val, param_key);
        return false;
      }

      return true;
    }
    else
    {
      static_assert(ccf::nonstd::dependent_false<T>::value, "Unsupported type");
      return false;
    }
  }

  template <typename T>
  static std::optional<T> get_query_value_opt(
    const ParsedQuery& pq,
    const std::string_view& param_key,
    std::string& error_reason)
  {
    T val;
    if (get_query_value(pq, param_key, val, error_reason))
    {
      return val;
    }
    else
    {
      return std::nullopt;
    }
  }
}
