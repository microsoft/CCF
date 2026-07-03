// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/nonstd.h"

#define FMT_HEADER_ONLY
#include <charconv>
#include <cctype>
#include <fmt/format.h>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace ccf::http
{
  // Query is parsed into a multimap, so that duplicate keys are retained.
  // Handling of duplicates (or ignoring them entirely) is left to the caller.
  using ParsedQuery = std::multimap<std::string, std::string>;

  static std::string url_decode_query_component(const std::string_view& s_)
  {
    std::string s(s_);
    char const* src = s.c_str();
    char const* end = s.c_str() + s.size();
    char* dst = s.data();

    while (src < end)
    {
      char const c = *src++;
      if (
        c == '%' && (src + 1) < end && (std::isxdigit(src[0]) != 0) &&
        (std::isxdigit(src[1]) != 0))
      {
        const auto a = ccf::ds::hex_char_to_int(*src++);
        const auto b = ccf::ds::hex_char_to_int(*src++);
        *dst++ = (a << 4) | b;
      }
      else if (c == '+')
      {
        *dst++ = ' ';
      }
      else
      {
        *dst++ = c;
      }
    }

    s.resize(dst - s.data());
    return s;
  }

  static ParsedQuery parse_query(const std::string_view& query)
  {
    ParsedQuery parsed;
    const auto params = ccf::nonstd::split(query, "&");
    for (const auto& param : params)
    {
      // NB: This means both `foo=` and `foo` will be accepted and result in a
      // `{"foo": ""}` in the map
      const auto& [key, value] = ccf::nonstd::split_1(param, "=");
      parsed.emplace(
        url_decode_query_component(key), url_decode_query_component(value));
    }

    return parsed;
  }

  template <typename T>
  static bool get_query_value(
    const ParsedQuery& pq,
    const std::string_view& param_key,
    T& val,
    std::string& error_reason)
  {
    const auto it = pq.find(std::string(param_key));

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
    else if constexpr (std::is_same_v<T, bool>)
    {
      if (param_val == "true")
      {
        val = true;
        return true;
      }

      if (param_val == "false")
      {
        val = false;
        return true;
      }

      error_reason = fmt::format(
        "Unable to parse value '{}' as bool in parameter '{}'",
        param_val,
        param_key);
      return false;
    }
    else if constexpr (std::is_integral_v<T>)
    {
      const auto* const end = param_val.data() + param_val.size();
      const auto [p, ec] = std::from_chars(param_val.data(), end, val);
      if (ec != std::errc() || p != end)
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
    return std::nullopt;
  }
}
