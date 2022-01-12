// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/rand.h>

#include "crypto/entropy.h"
#include "openssl_wrappers.h"

#include <functional>
#include <memory>
#include <vector>

namespace crypto
{
  class Entropy_OpenSSL : public Entropy
  {
  private:    
    static bool gen(uint64_t& v);

  public:
    Entropy_OpenSSL()
    {      
    }

    std::vector<uint8_t> random(size_t len) override
    {
      std::vector<uint8_t> data(len);

      if (RAND_bytes(data.data(), data.size()) != 1)
        throw std::logic_error("Couldn't create random data");

      return data;
    }

    uint64_t random64() override
    {
      uint64_t rnd;

      if (RAND_bytes((unsigned char*)&rnd, sizeof(uint64_t)) != 1) {
        throw std::logic_error("Couldn't create random data");
      }

      return rnd;
    }

    void random(unsigned char* data, size_t len) override
    {
      if (RAND_bytes(data, len) != 1) {
        throw std::logic_error("Couldn't create random data");
      }
    }

    // static int rng(void* ctx, unsigned char* output, size_t len)
    // {
    //   return mbedtls_ctr_drbg_random(ctx, output, len);
    // }

    // rng_func_t get_rng() override
    // {
    //   return &rng;
    // }

    // void* get_data() override
    // {
    //   return drbg.get();
    // }
  };
}
