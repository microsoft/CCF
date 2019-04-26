// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "intel_drng.h"
#include "tls.h"

#include <functional>
#include <memory>
#include <vector>

namespace tls
{
#if 1
  class Entropy : public IntelDRNG
  {
  public:
    Entropy() : IntelDRNG() {}
  };
#else
  class Entropy
  {
  private:
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;

    static bool gen(uint64_t& v);

  public:
    Entropy()
    {
      mbedtls_entropy_init(&entropy);
      mbedtls_ctr_drbg_init(&drbg);
      mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    }

    ~Entropy()
    {
      mbedtls_ctr_drbg_free(&drbg);
      mbedtls_entropy_free(&entropy);
    }

    std::vector<uint8_t> random(size_t len)
    {
      std::vector<uint8_t> data(len);

      if (mbedtls_ctr_drbg_random(&drbg, data.data(), data.size()) != 0)
        throw std::logic_error("Couldn't create random data");

      return data;
    }

    static int rng(void* ctx, unsigned char* output, size_t len)
    {
      Entropy* e = reinterpret_cast<Entropy*>(ctx);
      return mbedtls_ctr_drbg_random(&e->drbg, output, len);
    }
  };
#endif
}
