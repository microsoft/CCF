// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "error_string.h"

#include <mbedtls/base64.h>
#include <string>
#include <vector>

namespace tls
{
  inline std::vector<uint8_t> raw_from_b64(const std::string_view& b64_string)
  {
    size_t len_written;
    std::vector<uint8_t> raw(b64_string.begin(), b64_string.end());

    // Obtain the size of the output buffer
    auto rc =
      mbedtls_base64_decode(nullptr, 0, &len_written, raw.data(), raw.size());
    if (rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
      LOG_FAIL_FMT(fmt::format(
        "Could not obtain length of decoded base64 buffer: {}",
        error_string(rc)));
    }

    std::vector<uint8_t> decoded(len_written);

    rc = mbedtls_base64_decode(
      decoded.data(), decoded.size(), &len_written, raw.data(), raw.size());
    if (rc != 0)
    {
      LOG_FAIL_FMT(
        fmt::format("Could not decode base64 string: {}", error_string(rc)));
    }

    return decoded;
  }
}