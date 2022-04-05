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
    auto accepted_formats = {
      "%y%m%d%H%M%SZ", // ASN.1
      "%Y%m%d%H%M%SZ", // Generalized ASN.1
    };

    for (auto afmt : accepted_formats)
    {
      // Sadly %y in std::get_time seems to be broken, so strptime it is.
      // std::tm t;
      // std::istringstream ss(time);
      // ss >> std::get_time(&t, afmt);
      // if (ss) ...

      struct tm t;
      if (strptime(time.c_str(), afmt, &t) != NULL)
      {
        return std::chrono::system_clock::from_time_t(timegm(&t));
      }
    }

    throw std::runtime_error(
      fmt::format("'{}' does not match any accepted time format", time));
  }
}
