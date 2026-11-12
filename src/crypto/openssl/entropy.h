// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"

#include <functional>
#include <memory>
#include <openssl/rand.h>
#include <vector>

namespace ccf::crypto
{
  class Entropy_OpenSSL : public Entropy
  {
  private:
    static bool gen(uint64_t& v);

    // RAND_bytes takes an int length; RAND_bytes_ex takes the full size_t,
    // with the same default strength.
    static void fill(unsigned char* data, size_t len)
    {
      if (RAND_bytes_ex(nullptr, data, len, 0) != 1)
      {
        throw std::logic_error("Couldn't create random data");
      }
    }

  public:
    Entropy_OpenSSL() = default;

    std::vector<uint8_t> random(size_t len) override
    {
      std::vector<uint8_t> data(len);
      fill(data.data(), data.size());
      return data;
    }

    uint64_t random64() override
    {
      uint64_t rnd = 0;
      fill(reinterpret_cast<unsigned char*>(&rnd), sizeof(uint64_t));
      return rnd;
    }

    void random(unsigned char* data, size_t len) override
    {
      fill(data, len);
    }
  };
}
