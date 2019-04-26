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
    std::vector<uint8_t> v;

  public:
    Pem(CBuffer b)
    {
      if (b.n == 0)
        throw std::logic_error("Got PEM of size 0.");

      // has terminating zero?
      if (!b.p[b.n - 1])
      {
        p = b.p;
        n = b.n;
      }
      else
      {
        n = b.n + 1;
        if (n < b.n)
          throw std::overflow_error("integer overflow");
        v.resize(n);
        std::memcpy(v.data(), b.p, b.n);
        v[n - 1] = 0;
        p = v.data();
      }
    }

    const uint8_t* p;
    size_t n;
  };
}