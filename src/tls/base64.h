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
    size_t len_written = 0;
    const auto data = reinterpret_cast<const uint8_t*>(b64_string.data());
    const auto size = b64_string.size();

    // Obtain the size of the output buffer
    auto rc = mbedtls_base64_decode(nullptr, 0, &len_written, data, size);
    if (rc < 0 && rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
      throw std::logic_error(fmt::format(
        "Could not obtain length of decoded base64 buffer: {}",
        error_string(rc)));
    }

    std::vector<uint8_t> decoded(len_written);

    rc = mbedtls_base64_decode(
      decoded.data(), decoded.size(), &len_written, data, size);
    if (rc != 0)
    {
      throw std::invalid_argument(
        fmt::format("Could not decode base64 string: {}", error_string(rc)));
    }

    return decoded;
  }

  inline std::vector<uint8_t> raw_from_b64url(
    const std::string_view& b64url_string)
  {
    std::string b64_string = std::string(b64url_string);
    for (size_t i = 0; i < b64_string.size(); i++)
    {
      switch (b64_string[i])
      {
        case '-':
          b64_string[i] = '+';
          break;
        case '_':
          b64_string[i] = '/';
          break;
      }
    }
    auto padding =
      b64_string.size() % 4 == 2 ? 2 : b64_string.size() % 4 == 3 ? 1 : 0;
    b64_string += std::string(padding, '=');
    return raw_from_b64(b64_string);
  }

  inline std::string b64_from_raw(const uint8_t* data, size_t size)
  {
    size_t len_written = 0;

    // Obtain required size for output buffer
    auto rc = mbedtls_base64_encode(nullptr, 0, &len_written, data, size);
    if (rc < 0 && rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
      throw std::logic_error(fmt::format(
        "Could not obtain length required for encoded base64 buffer: {}",
        error_string(rc)));
    }

    std::string b64_string(len_written, '\0');
    auto dest = reinterpret_cast<uint8_t*>(b64_string.data());

    rc =
      mbedtls_base64_encode(dest, b64_string.size(), &len_written, data, size);
    if (rc != 0)
    {
      throw std::logic_error(
        fmt::format("Could not encode base64 string: {}", error_string(rc)));
    }

    if (b64_string.size() > 0)
    {
      // mbedtls includes the terminating null, but std-string provides this
      // already
      b64_string.pop_back();
    }

    return b64_string;
  }

  inline std::string b64_from_raw(const std::vector<uint8_t>& data)
  {
    return b64_from_raw(data.data(), data.size());
  }
}