// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "openssl_wrappers.h"

#include <time.h>

namespace crypto
{
  namespace OpenSSL
  {
    /** Validates that @time_before is not after @time_after.
     * If @allowed_diff_days is set, the time difference (in days) between
     * @time_before and @time_after should be less than or equal to its value.
     *
     * @param time_before The time to check.
     * @param time_after The time to check against.
     * @param allowed_diff_days The maximum allowed difference in days
     * (optional).
     *
     * @return True if @time_before is not after @time_after @allowed_diff_days.
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