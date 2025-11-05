// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace ccf::crypto
{
  class Entropy
  {
  public:
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
