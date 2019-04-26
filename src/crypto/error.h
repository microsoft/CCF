// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdexcept>

namespace crypto
{
  struct crypto_error : public std::runtime_error
  {
    explicit crypto_error(const char* msg) : std::runtime_error(msg) {}
  };
}
