// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/md_type.h"
#include "ccf/crypto/sha256_hash.h"
#include "ds/buffer.h"
#include "ds/hex.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

namespace crypto
{
  using HashBytes = std::vector<uint8_t>;

  class HashProvider
  {
  public:
    /** Generic Hash function
     * @param data The data to hash
     * @param size The size of @p data
     * @param type The type of hash to compute
     */
    virtual HashBytes Hash(
      const uint8_t* data, size_t size, MDType type) const = 0;

    virtual ~HashProvider() = default;
  };

  // Incremental Hash Objects
  class ISha256Hash
  {
  public:
    ISha256Hash() {}
    virtual ~ISha256Hash() {}

    virtual void update_hash(CBuffer data) = 0;
    virtual Sha256Hash finalise() = 0;

    template <typename T>
    void update(const T& t)
    {
      update_hash({reinterpret_cast<const uint8_t*>(&t), sizeof(T)});
    }

    template <>
    void update<std::vector<uint8_t>>(const std::vector<uint8_t>& d)
    {
      update_hash({d.data(), d.size()});
    }
  };
}
