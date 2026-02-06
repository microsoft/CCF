// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <chrono>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <time.h>
#include <vector>
namespace ccf::ds
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

  static inline std::string to_x509_time_string(
    const std::chrono::seconds& seconds_since_epoch)
  {
    return to_x509_time_string(fmt::gmtime(seconds_since_epoch.count()));
  }

  static inline std::chrono::seconds since_epoch_from_string(
    const std::string& time)
  {
    // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const char* ts = time.c_str();

    auto accepted_formats = {
      "%y%m%d%H%M%SZ", // ASN.1
      "%Y%m%d%H%M%SZ", // Generalized ASN.1
      "%Y-%m-%d %H:%M:%S"};

    for (const auto* afmt : accepted_formats)
    {
      // Sadly %y in std::get_time seems to be broken, so strptime it is.
      struct tm t = {};
      auto* sres = strptime(ts, afmt, &t);
      if (sres != nullptr && *sres == '\0')
      {
        auto r = timegm(&t);
        r -= t.tm_gmtoff;
        return std::chrono::seconds(r);
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
      unsigned y = 0;
      unsigned m = 0;
      unsigned d = 0;
      unsigned h = 0;
      unsigned mn = 0;
      unsigned om = 0;
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

          struct tm tm = {};
          tm.tm_year = y - 1900;
          tm.tm_mon = m - 1;
          tm.tm_mday = d;
          tm.tm_hour = h;
          tm.tm_min = mn;
          tm.tm_sec = (int)s;

          auto r = std::chrono::seconds(timegm(&tm));
          if (rs >= 8)
          {
            r -= hours(oh) + minutes(om);
          }
          return r;
        }
      }
    }
    // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    throw std::runtime_error(
      fmt::format("'{}' does not match any accepted time format", time));
  }

  static inline std::chrono::system_clock::time_point time_point_from_string(
    const std::string& time)
  {
    const auto s = since_epoch_from_string(time);

    static constexpr auto range_max =
      std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::time_point::max().time_since_epoch());
    static constexpr auto range_min =
      std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::time_point::min().time_since_epoch());

    if (s > range_max)
    {
      throw std::runtime_error(fmt::format(
        "'{}' is too far in the future to be represented as a "
        "system_clock::time_point",
        time));
    }

    if (s < range_min)
    {
      throw std::runtime_error(fmt::format(
        "'{}' is too far in the past to be represented as a "
        "system_clock::time_point",
        time));
    }

    return std::chrono::system_clock::time_point(s);
  }

  static inline std::string to_x509_time_string(const std::string& time)
  {
    return to_x509_time_string(time_point_from_string(time));
  }
}
