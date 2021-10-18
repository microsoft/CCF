// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "openssl_wrappers.h"

#include <fmt/format.h>
#include <time.h>

namespace crypto::OpenSSL
{
  /** Set of utilites functions for working with x509 time, as defined in RFC
  5280 (https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1) */

  static inline bool validate_chronological_times(
    const Unique_X509_TIME& time_before,
    const Unique_X509_TIME& time_after,
    const std::optional<uint32_t>& allowed_diff_days = std::nullopt)
  {
    int diff_days = 0;
    int diff_secs = 0;
    CHECK1(ASN1_TIME_diff(&diff_days, &diff_secs, time_before, time_after));

    return (diff_days > 0 || diff_secs > 0) &&
      (!allowed_diff_days.has_value() ||
       (unsigned int)diff_days <= allowed_diff_days.value());
  }

  static inline Unique_X509_TIME from_time_t(const time_t& t)
  {
    return Unique_X509_TIME(ASN1_TIME_set(nullptr, t));
  }

  static inline time_t to_time_t(const ASN1_TIME* time)
  {
    tm tm_time;
    CHECK1(ASN1_TIME_to_tm(time, &tm_time));
    return std::mktime(&tm_time);
  }

  static inline Unique_X509_TIME adjust_time(
    const Unique_X509_TIME& time, size_t offset_days, int64_t offset_secs = 0)
  {
    return Unique_X509_TIME(
      ASN1_TIME_adj(nullptr, to_time_t(time), offset_days, offset_secs));
  }

  static inline std::string to_x509_time_string(const time_t& time)
  {
    // Returns ASN1 time string (YYYYMMDDHHMMSSZ) from time_t, as per
    // https://www.openssl.org/docs/man1.1.1/man3/ASN1_UTCTIME_set.html
    return fmt::format("{:%Y%m%d%H%M%SZ}", fmt::gmtime(time));
  }

  static inline std::string to_x509_time_string(const ASN1_TIME* time)
  {
    return to_x509_time_string(to_time_t(time));
  }
}
