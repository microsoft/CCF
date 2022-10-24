// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/x509_time_fmt.h"
#include "openssl_wrappers.h"

#include <openssl/asn1.h>

namespace crypto::OpenSSL
{
  /** Set of utilities functions for working with x509 time, as defined in RFC
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

  static inline std::string to_x509_time_string(const ASN1_TIME* time)
  {
    std::tm t;
    CHECK1(ASN1_TIME_to_tm(time, &t));
    return ds::to_x509_time_string(t);
  }
}
