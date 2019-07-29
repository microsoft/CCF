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
  // convenience class ensuring null termination of PEM-encoded certificates as
  // required by mbedTLS
  class Pem
  {
  public:
    std::string s;

    Pem(CBuffer b)
    {
      if (b.n == 0)
        throw std::logic_error("Got PEM of size 0.");

      s.assign(reinterpret_cast<const char*>(b.p), b.n);
    }

    uint8_t* data()
    {
      return reinterpret_cast<uint8_t*>(s.data());
    }

    size_t size() const
    {
      return s.size();
    }
  };
}