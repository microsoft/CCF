// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/buffer.h"
#include "tls.h"

#include <cstring>
#include <exception>
#include <memory>
#include <vector>

namespace tls
{
  // Convenience class ensuring null termination of PEM-encoded certificates as
  // required by mbedTLS
  class Pem
  {
    std::string s;

  public:
    Pem() = default;

    Pem(const std::string& s_) : s(s_) {}

    Pem(CBuffer b)
    {
      // TODO: https://github.com/microsoft/CCF/issues/601
      if (b.n == 0)
        throw std::logic_error("Got PEM of size 0.");

      s.assign(reinterpret_cast<const char*>(b.p), b.n);
    }

    const std::string& str() const
    {
      return s;
    }

    uint8_t* data()
    {
      return reinterpret_cast<uint8_t*>(s.data());
    }

    const uint8_t* data() const
    {
      return reinterpret_cast<const uint8_t*>(s.data());
    }

    size_t size() const
    {
      // +1 for null termination
      return s.size() + 1;
    }
  };
}