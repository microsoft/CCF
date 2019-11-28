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
    Pem(){};

    Pem(CBuffer b)
    {
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

    std::vector<uint8_t> raw() const
    {
      const auto cert_data = data();
      auto cert_len = strlen((char*)cert_data) + 1;

      return {cert_data, cert_data + cert_len};
    }

    size_t size() const
    {
      return s.size();
    }
  };
}