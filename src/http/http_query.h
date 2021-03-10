// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/nonstd.h"

#include <charconv>
#include <map>
#include <string_view>

namespace http
{
  // Query is parsed into a multimap, so that duplicate keys are retained.
  // Handling of duplicates (or ignoring them entirely) is left to the caller.
  // Keys and values are both string_views, pointing at subranges of original
  // query string.
  using ParsedQuery = std::multimap<std::string_view, std::string_view>;

  static inline ParsedQuery parse_query(const std::string_view& query) {
    ParsedQuery parsed;
    const auto params = nonstd::split(query, "&");
    for (const auto& param: params)
    {
      // NB: This means both `foo=` and `foo` will be accepted and result in a `{"foo": ""}` in the map
      const auto& [key, value] = nonstd::split_1(param, "=");
      parsed.emplace(key, value);
    }

    return parsed;
  }

  template <typename T>
  static bool get_query_value(const ParsedQuery& pq, const std::string_view& param_key, T& val, std::string& error_reason)
  {
    const auto it = pq.find(param_key);

    if (it == pq.end())
    {
      error_reason = fmt::format("Missing query parameter '{}'", param_key);
      return false;
    }

    const std::string_view& param_val = it->second;

    if constexpr (std::is_same_v<T, std::string>)
    {
      val = T(param_val);
      return true;
    }
    else if constexpr (std::is_integral_v<T>)
    {
      const auto [p, ec] =
        std::from_chars(param_val.begin(), param_val.end(), val);
      if (ec != std::errc() || p != param_val.end())
      {
        error_reason = 
          fmt::format(
            "Unable to parse value '{}' in parameter '{}'",
            param_val,
            param_key);
        return false;
      }

      return true;
    }
    else
    {
      static_assert(
        nonstd::dependent_false<T>::value,
        "Unsupported type");
      return false;
    }
  }
}
