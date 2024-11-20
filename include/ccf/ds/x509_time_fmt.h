// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <chrono>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <iomanip>
#include <sstream>
#include <time.h>
#include <vector>

namespace ds
{
  static inline std::string to_x509_time_string(const std::tm& time)
  {
    // Returns ASN1 time string (YYYYMMDDHHMMSSZ) from time_t, as per
    // https://www.openssl.org/docs/man1.1.1/man3/ASN1_UTCTIME_set.html
    return fmt::format("{:%Y%m%d%H%M%SZ}", time);
  }

  static inline std::string to_x509_time_string(
    const std::chrono::system_clock::time_point& time)
  {
    return to_x509_time_string(fmt::gmtime(time));
  }

  static inline std::chrono::system_clock::time_point time_point_from_string(
    const std::string& time)
  {
    const char* ts = time.c_str();

    auto accepted_formats = {
      "%y%m%d%H%M%SZ", // ASN.1
      "%Y%m%d%H%M%SZ", // Generalized ASN.1
      "%Y-%m-%d %H:%M:%S"};

    for (auto afmt : accepted_formats)
    {
      // Sadly %y in std::get_time seems to be broken, so strptime it is.
      struct tm t = {};
      auto sres = strptime(ts, afmt, &t);
      if (sres != NULL && *sres == '\0')
      {
        auto r = std::chrono::system_clock::from_time_t(timegm(&t));
        r -= std::chrono::seconds(t.tm_gmtoff);
        return r;
      }
    }

    // Then there are formats that strptime doesn't support...
    std::vector<std::pair<const char*, int>> more_formats = {
      // Note: longest format to match first
      {"%04u-%02u-%02u %02u:%02u:%f %d:%02u", 8},
      {"%04u-%02u-%02uT%02u:%02u:%f %d:%02u", 8},
      {"%04u-%02u-%02u %02u:%02u:%f %03d %02u", 8},
      {"%02u%02u%02u%02u%02u%02f%03d%02u", 8},
      {"%04u%02u%02u%02u%02u%02f%03d%02u", 8},
      {"%04u-%02u-%02uT%02u:%02u:%f", 6},
      {"%04u-%02u-%02u %02u:%02u:%f", 6}};

    for (auto [fmt, n] : more_formats)
    {
      unsigned y = 0, m = 0, d = 0, h = 0, mn = 0, om = 0;
      int oh = 0;
      float s = 0.0;

      int rs = sscanf(ts, fmt, &y, &m, &d, &h, &mn, &s, &oh, &om);
      if (rs >= 1 && rs == n)
      {
        using namespace std::chrono;

        if (strncmp(fmt, "%02u", 4) == 0)
        {
          // ASN.1 two-digit year range
          y += y >= 50 ? 1900 : 2000;
        }

        if (rs >= 3)
        {
          auto date = year_month_day(year(y), month(m), day(d));

          if (
            !date.ok() || (rs >= 6 && (h > 24 || mn > 60 || s < 0.0)) ||
            (rs >= 8 && (s > 60.0 || oh < -23 || oh > 23 || om > 60)))
          {
            continue;
          }

          system_clock::time_point r = (sys_days)date;
          if (rs >= 6)
            r += hours(h) + minutes(mn) + microseconds((long)(s * 1e6));
          if (rs >= 8)
            r -= hours(oh) + minutes(om);
          return r;
        }
      }
    }

    throw std::runtime_error(
      fmt::format("'{}' does not match any accepted time format", time));
  }

  static inline std::string to_x509_time_string(const std::string& time)
  {
    return to_x509_time_string(time_point_from_string(time));
  }
}
