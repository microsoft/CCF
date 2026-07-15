// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/nonstd.h"

#define FMT_HEADER_ONLY
#include <cctype>
#include <charconv>
#include <fmt/format.h>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace ccf::http
{
  // Query is parsed into a multimap, so that duplicate keys are retained.
  // Handling of duplicates (or ignoring them entirely) is left to the caller.
  // The map owns its decoded keys and values: they cannot be string_views into
  // the source query, since percent-decoding produces bytes not present there.
  // std::less<> is a transparent comparator, so the map can still be looked up
  // with a std::string_view key without constructing a temporary std::string.
  using ParsedQuery = std::multimap<std::string, std::string, std::less<>>;

  // Percent-decodes a single query-string component (a key or a value that has
  // already been split out of the raw query): '%XX' escapes are decoded to the
  // corresponding byte, '+' is decoded to a space, and malformed or truncated
  // escapes ('%', '%2', '%zz') are passed through literally rather than
  // throwing. This is the same percent-decoding used by http::url_decode for
  // path fragments; query components must be decoded individually, after
  // splitting on '&' and '=', so that escaped separators are preserved.
  static std::string decode_query_component(const std::string_view& s)
  {
    std::string decoded;
    decoded.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
      const char c = s[i];
      if (c == '%' && i + 2 < s.size())
      {
        const auto hi = s[i + 1];
        const auto lo = s[i + 2];
        if (
          std::isxdigit(static_cast<unsigned char>(hi)) != 0 &&
          std::isxdigit(static_cast<unsigned char>(lo)) != 0)
        {
          const auto a = ccf::ds::hex_char_to_int(hi);
          const auto b = ccf::ds::hex_char_to_int(lo);
          decoded.push_back((a << 4) | b);
          i += 2;
        }
        else
        {
          decoded.push_back(c);
        }
      }
      else if (c == '+')
      {
        decoded.push_back(' ');
      }
      else
      {
        decoded.push_back(c);
      }
    }

    return decoded;
  }

  // Parses a raw (still percent-encoded) query string into a ParsedQuery. The
  // query is split on '&' into parameters, then each parameter on its first
  // '=' into a key and value; every key and value is then percent-decoded
  // individually (see decode_query_component). Splitting before decoding means
  // escaped separators are preserved: "a%26b=c%3Dd" yields key "a&b", value
  // "c=d". Both "foo" and "foo=" yield an empty value, and duplicate keys are
  // all retained in order.
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
        decode_query_component(key), decode_query_component(value));
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
    const auto it = pq.find(param_key);

    if (it == pq.end())
    {
      error_reason = fmt::format("Missing query parameter '{}'", param_key);
      return false;
    }

    const std::string& param_val = it->second;

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
      // Parsed query values are strings, so use data() because std::from_chars
      // requires contiguous character pointers rather than iterators.
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
