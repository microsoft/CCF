// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "openssl_wrappers.h"

#include <time.h>

namespace crypto
{
  namespace OpenSSL
  {
    /** Set of utilites functions for working with x509 time, as defined in RFC
    5280 (https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1) */

    /** Checks that two times are in chronological order, and optionally within
     * a certain time range.
     *
     * @param time_before The time to check
     * @param time_after The time to check against, which should be later than
     * \p time_before
     * @param allowed_diff_days The maximum allowed difference in days
     * (optional)
     *
     * @return True if \p time_before is chronologically before \p time_after,
     * and within \p allowed_diff_days days.
     */
    static inline bool validate_chronological_times(
      const Unique_ASN1_TIME& time_before,
      const Unique_ASN1_TIME& time_after,
      const std::optional<uint32_t>& allowed_diff_days = std::nullopt)
    {
      int diff_days = 0;
      int diff_secs = 0;
      CHECK1(ASN1_TIME_diff(&diff_days, &diff_secs, time_before, time_after));

      return diff_days > 0 &&
        (!allowed_diff_days.has_value() ||
         (unsigned int)diff_days <= allowed_diff_days.value());
    }

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
  }
}