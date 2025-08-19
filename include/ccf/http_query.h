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
#include <cctype>

namespace ccf::http
{
  // Simple URL decoding function
  static std::string url_decode(const std::string_view& s_)
  {
    std::string s(s_);
    char const* src = s.c_str();
    char const* end = s.c_str() + s.size();
    char* dst = s.data();

    while (src < end)
    {
      char const c = *src++;
      if (c == '%' && (src + 1) < end && std::isxdigit(src[0]) && std::isxdigit(src[1]))
      {
        // Convert hex chars to int
        auto hex_char_to_int = [](char c) -> int {
          if (c >= '0' && c <= '9') return c - '0';
          if (c >= 'A' && c <= 'F') return c - 'A' + 10;
          if (c >= 'a' && c <= 'f') return c - 'a' + 10;
          return 0;
        };
        const auto a = hex_char_to_int(*src++);
        const auto b = hex_char_to_int(*src++);
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

namespace ccf::http
{
  // Query is parsed into a multimap, so that duplicate keys are retained.
  // Handling of duplicates (or ignoring them entirely) is left to the caller.
  // Keys and values are URL-decoded strings.
  using ParsedQuery = std::multimap<std::string, std::string>;

  static ParsedQuery parse_query(const std::string_view& query)
  {
    ParsedQuery parsed;
    
    // Find parameter boundaries by looking for unescaped '&' characters
    std::vector<std::string_view> params;
    size_t start = 0;
    size_t pos = 0;
    
    while (pos < query.length())
    {
      if (query[pos] == '%' && pos + 2 < query.length() && 
          std::isxdigit(query[pos + 1]) && std::isxdigit(query[pos + 2]))
      {
        // Skip URL-encoded sequence
        pos += 3;
      }
      else if (query[pos] == '&')
      {
        // Found parameter separator - always add the parameter, even if empty
        params.push_back(query.substr(start, pos - start));
        start = pos + 1;
        pos = start;
      }
      else
      {
        pos++;
      }
    }
    
    // Add the last parameter
    if (start <= query.length())  // Use <= instead of < to handle trailing &
    {
      params.push_back(query.substr(start));
    }
    
    // Parse each parameter 
    for (const auto& param : params)
    {
      // Don't skip empty params - they should create entries with empty keys
      
      // Find the first unescaped '=' character
      size_t eq_pos = std::string_view::npos;
      size_t i = 0;
      while (i < param.length())
      {
        if (param[i] == '%' && i + 2 < param.length() &&
            std::isxdigit(param[i + 1]) && std::isxdigit(param[i + 2]))
        {
          // Skip URL-encoded sequence
          i += 3;
        }
        else if (param[i] == '=' && eq_pos == std::string_view::npos)
        {
          // Found the first unescaped equals sign
          eq_pos = i;
          break;
        }
        else
        {
          i++;
        }
      }
      
      std::string_view encoded_key, encoded_value;
      if (eq_pos != std::string_view::npos)
      {
        encoded_key = param.substr(0, eq_pos);
        encoded_value = param.substr(eq_pos + 1);
      }
      else
      {
        // No '=' found, treat entire param as key with empty value
        encoded_key = param;
        encoded_value = "";
      }
      
      // URL-decode the key and value
      std::string decoded_key = url_decode(encoded_key);
      std::string decoded_value = url_decode(encoded_value);
      
      parsed.emplace(std::move(decoded_key), std::move(decoded_value));
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
      const auto [p, ec] =
        std::from_chars(param_val.begin(), param_val.end(), val);
      if (ec != std::errc() || p != param_val.end())
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
