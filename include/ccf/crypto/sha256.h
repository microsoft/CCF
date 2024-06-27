// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_bytes.h"

#include <vector>

namespace ccf::crypto
{
  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   *
   * @return hashed value
   */
  HashBytes sha256(const std::span<uint8_t const>& data);

  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   * @param len Length of the data
   *
   * @return hashed value
   */
  HashBytes sha256(const uint8_t* data, size_t len);
}
