// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <mbedtls/error.h>
#include <string>

namespace tls
{
  inline std::string error_string(int err)
  {
    constexpr size_t len = 256;
    char buf[len];
    mbedtls_strerror(err, buf, len);

    if (strlen(buf) == 0)
    {
      return std::to_string(err);
    }

    return std::string(buf);
  }
}