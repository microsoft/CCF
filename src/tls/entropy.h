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
  static bool use_drng = IntelDRNG::is_drng_supported();
  using EntropyPtr = std::shared_ptr<Entropy>;
  static EntropyPtr intel_drng_ptr;
  EntropyPtr create_entropy();

  class MbedtlsEntropy : public Entropy
  {
  private:
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;

    static bool gen(uint64_t& v);

  public:
    MbedtlsEntropy()
    {
      mbedtls_entropy_init(&entropy);
      mbedtls_ctr_drbg_init(&drbg);
      mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    }

    ~MbedtlsEntropy()
    {
      mbedtls_ctr_drbg_free(&drbg);
      mbedtls_entropy_free(&entropy);
    }

    std::vector<uint8_t> random(size_t len) override
    {
      std::vector<uint8_t> data(len);

      if (mbedtls_ctr_drbg_random(&drbg, data.data(), data.size()) != 0)
        throw std::logic_error("Couldn't create random data");

      return data;
    }

    static int rng(void* ctx, unsigned char* output, size_t len)
    {
      MbedtlsEntropy* e = reinterpret_cast<MbedtlsEntropy*>(ctx);
      return mbedtls_ctr_drbg_random(&e->drbg, output, len);
    }

    rng_func_t get_rng() override
    {
      return &rng;
    }

    void* get_data() override
    {
      return this;
    }
  };

  inline EntropyPtr create_entropy()
  {
    if (use_drng)
    {
      if (!intel_drng_ptr)
        intel_drng_ptr = std::make_shared<IntelDRNG>();
      return intel_drng_ptr;
    }

    return std::make_shared<MbedtlsEntropy>();
  }

}
