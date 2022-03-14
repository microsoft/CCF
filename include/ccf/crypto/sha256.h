// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_bytes.h"

#include <vector>

namespace crypto
{
  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   */
  HashBytes sha256(const std::vector<uint8_t>& data);

  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   * @param len Length of the data
   */
  HashBytes sha256(const uint8_t* data, size_t len);
}
