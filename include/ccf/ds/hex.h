// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <span>
#include <string>
#include <vector>

namespace ccf::ds
{
  constexpr size_t ascii_offset = 10;
  static uint8_t hex_char_to_int(char c)
  {
    if (c <= '9')
    {
      return c - '0';
    }

    if (c <= 'F')
    {
      return c - 'A' + ascii_offset;
    }

    if (c <= 'f')
    {
      return c - 'a' + ascii_offset;
    }

    return c;
  }

  // Notes: uses lowercase for 'abcdef' characters
  template <typename Iter>
  inline static std::string to_hex(Iter begin, Iter end)
  {
    return fmt::format("{:02x}", fmt::join(begin, end, ""));
  }

  template <typename T>
  inline static std::string to_hex(const T& data)
  {
    return to_hex(data.begin(), data.end());
  }

  inline static std::string to_hex(std::span<const uint8_t> buf)
  {
    std::string r;
    for (auto c : buf)
    {
      r += fmt::format("{:02x}", c);
    }
    return r;
  }

  constexpr size_t hex_base = 16;

  template <typename Iter>
  static void from_hex(const std::string& str, Iter begin, Iter end)
  {
    if ((str.size() & 1) != 0)
    {
      throw std::logic_error(fmt::format(
        "Input string '{}' is not of even length: {}", str, str.size()));
    }

    if (std::distance(begin, end) != str.size() / 2)
    {
      throw std::logic_error(fmt::format(
        "Output container of size {} cannot fit decoded hex str {}",
        std::distance(begin, end),
        str.size() / 2));
    }

    auto it = begin;
    for (size_t i = 0; i < str.size(); i += 2, ++it)
    {
      *it = hex_base * hex_char_to_int(str[i]) + hex_char_to_int(str[i + 1]);
    }
  }

  inline static std::vector<uint8_t> from_hex(const std::string& str)
  {
    std::vector<uint8_t> ret(str.size() / 2);
    from_hex(str, ret.begin(), ret.end());
    return ret;
  }

  template <typename T>
  inline static void from_hex(const std::string& str, T& out)
  {
    from_hex(str, out.begin(), out.end());
  }
}