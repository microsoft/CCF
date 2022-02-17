// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/md_type.h"

#include <vector>

namespace crypto
{
  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   */
  std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   * @param len Length of the data
   */
  std::vector<uint8_t> sha256(const uint8_t* data, size_t len);

  /** Perform HKDF key derivation */
  std::vector<uint8_t> hkdf(
    MDType md_type,
    size_t length,
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt = {},
    const std::vector<uint8_t>& info = {});
}
