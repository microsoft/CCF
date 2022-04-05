// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <time.h>

namespace ds
{
  static inline std::string to_x509_time_string(const time_t& time)
  {
    // Returns ASN1 time string (YYYYMMDDHHMMSSZ) from time_t, as per
    // https://www.openssl.org/docs/man1.1.1/man3/ASN1_UTCTIME_set.html
    return fmt::format("{:%Y%m%d%H%M%SZ}", fmt::gmtime(time));
  }
}