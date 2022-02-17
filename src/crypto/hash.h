// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "hash_provider.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <ostream>

namespace crypto
{
  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   */
  // TODO: Function, should be sha256
  std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data);

  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   * @param len Length of the data
   */
  std::vector<uint8_t> SHA256(const uint8_t* data, size_t len);

  /** Create a default hash provider */
  std::shared_ptr<HashProvider> make_hash_provider();

  /** Create a default incremental SHA256 hash provider */
  std::shared_ptr<ISha256Hash> make_incremental_sha256();

  /** Perform HKDF key derivation */
  std::vector<uint8_t> hkdf(
    MDType md_type,
    size_t length,
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt = {},
    const std::vector<uint8_t>& info = {});
}
