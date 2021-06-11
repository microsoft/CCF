// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <iostream>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#ifndef LOG_DEBUG_FMT
#  define LOG_DEBUG_FMT(s, ...) \
    std::cout << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl
#endif

#ifndef LOG_TRACE_FMT
#  define LOG_TRACE_FMT(s, ...) \
    std::cout << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl
#endif

#ifndef LOG_INFO_FMT
#  define LOG_INFO_FMT(s, ...) \
    std::cout << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl
#endif

namespace SplitIdentity
{
  static inline std::string to_hex(const std::vector<uint8_t>& bytes)
  {
    std::string r;
    r.resize(bytes.size() * 2);
    for (size_t i = 0; i < bytes.size(); i++)
    {
      sprintf(&r.data()[2 * i], "%02x", bytes[i]);
    }
    return r;
  }

  static inline std::vector<uint8_t> from_hex(const std::string& data)
  {
    std::vector<uint8_t> r;
    r.reserve(data.size() / 2);
    for (size_t i = 0; i < data.size(); i += 2)
    {
      uint8_t t;
      sscanf(&data.data()[i], "%02hhx", &t);
      r.push_back(t);
    }
    return r;
  }
}
