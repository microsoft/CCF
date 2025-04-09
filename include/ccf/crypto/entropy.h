// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/hardware_info.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

// Adapted from:
// https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide

#define DRNG_NO_SUPPORT 0x0
#define DRNG_HAS_RDRAND 0x1
#define DRNG_HAS_RDSEED 0x2

// `It is recommended that applications attempt 10 retries in a tight loop in
// the unlikely event that the RDRAND instruction does not return a random
// number. This number is based on a binomial probability argument: given
// the design margins of the DRNG, the odds of ten failures in a row are
// astronomically small and would in fact be an indication of a larger CPU
// issue.`
#define RDRAND_RETRIES 10

namespace ccf::crypto
{
  class Entropy
  {
  public:
    Entropy() = default;
    virtual ~Entropy() = default;

    /// Generate @p len random bytes
    /// @param len Number of random bytes to generate
    /// @return vector random bytes
    virtual std::vector<uint8_t> random(size_t len) = 0;

    /// Generate @p len random bytes into @p data
    /// @param len Number of random bytes to generate
    /// @param data Buffer to fill
    virtual void random(unsigned char* data, size_t len) = 0;

    /// Generate a random uint64_t
    /// @return a random uint64_t
    virtual uint64_t random64() = 0;
  };

  using EntropyPtr = std::shared_ptr<Entropy>;

  EntropyPtr get_entropy();
}
