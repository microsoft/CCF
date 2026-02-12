// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_bytes.h"
#include "ccf/crypto/md_type.h"
#include "ccf/crypto/sha256_hash.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

namespace ccf::crypto
{
  class HashProvider
  {
  public:
    /** Generic Hash function
     * @param data The data to hash
     * @param size The size of @p data
     * @param type The type of hash to compute
     */
    virtual HashBytes hash(
      const uint8_t* data, size_t size, MDType type) const = 0;

    virtual ~HashProvider() = default;
  };

  /** Create a default hash provider */
  std::shared_ptr<HashProvider> make_hash_provider();

  // Incremental Hash Objects
  class ISha256Hash
  {
  public:
    ISha256Hash() = default;
    virtual ~ISha256Hash() = default;

    virtual void update_hash(std::span<const uint8_t> data) = 0;
    virtual Sha256Hash finalise() = 0;

    template <typename T>
    void update(const T& t)
    {
      update_hash({reinterpret_cast<const uint8_t*>(&t), sizeof(T)});
    }

    template <>
    void update(const std::vector<uint8_t>& t)
    {
      update_hash(t);
    }
  };

  /** Create a default incremental SHA256 hash provider */
  std::shared_ptr<ISha256Hash> make_incremental_sha256();
}
