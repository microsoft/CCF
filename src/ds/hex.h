#pragma once

#include "ds/logger.h"

#include <fmt/format.h>
#include <string>
#include <vector>

namespace ds
{
  static uint8_t hex_char_to_int(char c)
  {
    if (c <= '9')
    {
      return c - '0';
    }
    else if (c <= 'F')
    {
      return c - 'A' + 10;
    }
    else if (c <= 'f')
    {
      return c - 'a' + 10;
    }
    return c;
  }

  // Notes: uses lowercase for 'abcdef' characters
  template <typename Iter>
  inline static std::string to_hex(Iter begin, Iter end)
  {
    return fmt::format("{:02x}", fmt::join(begin, end, ""));
  }

  inline static std::string to_hex(const std::vector<uint8_t>& data)
  {
    return to_hex(data.begin(), data.end());
  }

  template <size_t T>
  inline static std::string to_hex(const std::array<uint8_t, T>& data)
  {
    return to_hex(data.begin(), data.end());
  }

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
    for (size_t i = 0; i < str.size(); i += 2)
    {
      *it = 16 * hex_char_to_int(str[i]) + hex_char_to_int(str[i + 1]);
    }
  }

  inline static std::vector<uint8_t> from_hex(const std::string& str)
  {
    std::vector<uint8_t> ret(str.size() / 2);
    from_hex(str, ret.begin(), ret.end());
    return ret;
  }
}