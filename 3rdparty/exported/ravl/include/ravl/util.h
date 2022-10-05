// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

namespace ravl
{
  inline size_t replace_all(
    std::string& inout, std::string_view what, std::string_view with)
  {
    size_t count = 0;
    for (std::string::size_type pos = 0;
         inout.npos != (pos = inout.find(what.data(), pos, what.length()));
         pos += with.length(), ++count)
    {
      inout.replace(pos, what.length(), with.data(), with.length());
    }
    return count;
  }

  inline std::string& indentate_inplace(std::string& inout, size_t indent)
  {
    std::string ins(indent, ' ');
    replace_all(inout, "\n", "\n" + ins);
    inout = ins + inout;
    return inout;
  }

  inline std::string indentate(const std::string& in, size_t indent)
  {
    std::string r = in, ins(indent, ' ');
    replace_all(r, "\n", "\n" + ins);
    r = ins + r;
    return r;
  }

  inline std::string vec2str(const std::vector<uint8_t>& vec, size_t indent = 0)
  {
    auto r = std::string((char*)vec.data(), vec.size());
    if (indent > 0)
      indentate_inplace(r, indent);
    return r;
  }

  inline void log(const std::string& msg, size_t indent = 0)
  {
    std::cout << std::string(indent, ' ') << msg << std::endl;
  }

  template <typename T>
  T get(const std::vector<uint8_t>& data, size_t& pos)
  {
    if (pos + sizeof(T) > data.size())
      throw std::runtime_error("not enough data");

    T r = 0;
    for (size_t i = 0; i < sizeof(T); i++)
      r = r << 8 | data.at(pos + i);
    pos += sizeof(T);
    return r;
  }

  inline std::vector<uint8_t> get_n(
    const std::vector<uint8_t>& data, size_t n, size_t& pos)
  {
    if (pos + n > data.size())
      throw std::runtime_error("not enough data");

    std::vector<uint8_t> r(n, 0);
    for (size_t i = 0; i < n; i++)
      r[i] = data.at(pos + i);
    pos += n;

    return r;
  }

  template <typename T>
  inline void put(const T& t, const uint8_t* data, size_t& pos)
  {
    for (size_t i = 0; i < sizeof(T); i++)
      data[pos + i] = (t >> (8 * (sizeof(T) - i - 1))) & 0xFF;
    pos += sizeof(T);
  }

  template <typename T>
  inline void put(const T& t, std::vector<uint8_t>& data)
  {
    for (size_t i = 0; i < sizeof(T); i++)
      data.push_back((t >> (8 * (sizeof(T) - i - 1))) & 0xFF);
  }

  inline std::vector<uint8_t> from_hex(const std::string& s)
  {
    if (s.size() % 2)
      throw std::runtime_error("odd number of hex digits");

    std::vector<uint8_t> r;
    for (size_t i = 0; i < s.size(); i += 2)
    {
      uint8_t t;
      if (sscanf(s.c_str() + i, "%02hhx", &t) != 1)
        return {};
      r.push_back(t);
    }
    return r;
  }

  template <typename T>
  T from_hex_t(const std::string& s, bool little_endian = true)
  {
    if (s.size() % 2)
      throw std::runtime_error("odd number of hex digits");

    if (2 * sizeof(T) != s.size())
      throw std::runtime_error("hex string incomplete");

    T r = 0;
    for (size_t i = 0; i < sizeof(T); i++)
    {
      uint8_t t;
      if (sscanf(s.c_str() + 2 * i, "%02hhx", &t) != 1)
        return {};
      if (little_endian)
        r |= ((uint64_t)t) << (8 * i);
      else
        r = (r << 8) | t;
    }
    return r;
  }

  // From http://www.geekhideout.com/urlcode.shtml
  inline char from_hex(char ch)
  {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
  }

  inline std::string to_hex(const std::span<uint8_t>& v)
  {
    std::string r;
    r.reserve(v.size() * 2);
    for (const auto& b : v)
    {
      char buf[3];
      snprintf(buf, sizeof(buf), "%02x", b);
      r += buf;
    }
    return r;
  }

    inline void verify_within(
      const void* ptr, const std::span<const uint8_t>& vec)
    {
      if (!(vec.data() <= ptr && ptr < (vec.data() + vec.size())))
      throw std::runtime_error("invalid pointer");
    }

  inline void verify_within(
    const std::span<const uint8_t>& span, const std::span<const uint8_t>& vec)
  {
    verify_within(span.data(), vec);
    verify_within(span.data() + span.size() - 1, vec);
  }

  inline std::vector<uint8_t> str2vec(const std::string& s)
  {
    return {s.data(), s.data() + s.size()};
  }

  inline bool is_all_zero(const std::vector<uint8_t>& v)
  {
    for (const auto& b : v)
        if (b != 0)
        return false;
    return true;
  }

  inline std::chrono::system_clock::time_point parse_time_point(
    const std::string& s, const std::string& format)
  {
    struct tm stm = {};
    auto sres = strptime(s.c_str(), format.c_str(), &stm);
    if (sres == NULL || *sres != '\0')
      throw std::runtime_error("time point parsing failure");
    auto idr = std::chrono::system_clock::from_time_t(timegm(&stm));
    idr -= std::chrono::seconds(stm.tm_gmtoff);
    return idr;
  }

  template <size_t sz, typename FROM_TYPE>
  inline void copy(std::array<uint8_t, sz>& to, const FROM_TYPE& from)
  {
    std::copy(std::begin(from), std::end(from), std::begin(to));
  }

  // From http://www.geekhideout.com/urlcode.shtml

  /* Returns a url-decoded version of str */
  /* IMPORTANT: be sure to free() the returned string after use */
  inline char* url_decode(const char* str, size_t len)
  {
    const char* pstr = str;
    char *buf = (char*)malloc(len + 1), *pbuf = buf;
    while (*pstr)
    {
      if (*pstr == '%')
      {
        if (pstr[1] && pstr[2])
        {
          *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
          pstr += 2;
        }
      }
      else if (*pstr == '+')
        *pbuf++ = ' ';
      else
        *pbuf++ = *pstr;
      pstr++;
    }
    *pbuf = '\0';
    return buf;
  }
}
