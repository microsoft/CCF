// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "openssl_wrappers.h"

#include <fmt/format.h>
#include <time.h>

namespace crypto
{
  // TODO: ASN1_TIME or ASN1_GENERALIZEDTIME?

  namespace OpenSSL
  {
    /** Set of utilites functions for working with x509 time, as defined in RFC
    5280 (https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1) */

    static inline Unique_ASN1_TIME from_time_t(const time_t& t)
    {
      return Unique_ASN1_TIME(ASN1_TIME_set(nullptr, t));
    }

    static inline time_t to_time_t(const Unique_ASN1_TIME& time)
    {
      tm tm_time;
      CHECK1(ASN1_TIME_to_tm(time, &tm_time));
      return std::mktime(&tm_time);
    }

    static inline Unique_ASN1_TIME adjust_time(
      const Unique_ASN1_TIME& time, size_t offset_days, int64_t offset_secs = 0)
    {
      return Unique_ASN1_TIME(
        ASN1_TIME_adj(nullptr, to_time_t(time), offset_days, offset_secs));
    }

    static inline std::string to_x509_time_string(const time_t& time)
    {
      // Returns ASN1 time string (YYYYMMDDHHMMSSZ) from time_t, as per
      // https://www.openssl.org/docs/man1.1.1/man3/ASN1_UTCTIME_set.html
      return fmt::format("{:%y%m%d%H%M%SZ}", fmt::gmtime(time));
    }
  }
}